//go:build integration
// +build integration

package integration

// What the exit provider is for.
//
// An operator leaving the product switches the active provider to `exit` and
// keeps the provider that holds the old key registered next to it
// (config/exit-example.yaml). From then on the decision is per object, not per
// provider, and a bucket legitimately holds both kinds:
//
//   - an object this proxy encrypted before the switch still decrypts, because
//     the object's own s3ep-kek-fingerprint names the provider that wrapped its
//     data key, and that provider is still configured;
//   - an object written after the switch is stored as the client sent it, with
//     no data key and no s3ep-* metadata, and is served back verbatim.
//
// Three write paths lead here - one PUT request below the segment size, the
// multipart producer above it, and the client's own multipart upload - and each
// had to be changed separately, so each is exercised below. Content is compared
// by SHA-256 (assertDataHashesEqual in test_helpers.go), never by dumping bytes.
//
// The alias under which the key is registered is deliberately not the one the
// writing proxy used: aes-example.yaml calls it "aes-envelope" and
// exit-example.yaml calls it "aes-previous". The fingerprint is derived from
// the key, not from the alias, so the object still finds its provider.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	. "github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomPayload returns n bytes that no compressor and no entropy check can
// mistake for plaintext structure.
func randomPayload(t *testing.T, n int) []byte {
	t.Helper()

	payload := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, payload)
	require.NoError(t, err, "failed to generate %d bytes of test data", n)
	return payload
}

// getViaClient reads a whole object and returns its body.
func getViaClient(t *testing.T, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	resp, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "GET %s/%s", bucket, key)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading %s/%s", bucket, key)
	return data
}

// storedObject returns what the backend actually holds, read directly from
// MinIO so the proxy has no chance to decrypt it on the way.
func storedObject(t *testing.T, minioClient *s3.Client, bucket, key string) ([]byte, map[string]string) {
	t.Helper()

	resp, err := minioClient.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "reading %s/%s straight from the backend", bucket, key)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading the stored bytes of %s/%s", bucket, key)
	return data, resp.Metadata
}

// assertStoredEncrypted asserts that the backend holds ciphertext this proxy
// wrote: different bytes, and the metadata that names the key.
func assertStoredEncrypted(t *testing.T, minioClient *s3.Client, bucket, key string, plaintext []byte) {
	t.Helper()

	stored, metadata := storedObject(t, minioClient, bucket, key)
	assertDataHashesNotEqual(t, plaintext, stored, "the backend must hold ciphertext, not the plaintext")
	assert.Contains(t, metadata, "s3ep-encrypted-dek", "an encrypted object carries its wrapped data key")
	assert.Contains(t, metadata, "s3ep-kek-fingerprint", "an encrypted object names the key that wrapped it")
	assert.Equal(t, "s3ep-gcm-seg-v2", metadata["s3ep-dek-algorithm"], "unexpected storage format")
}

// assertStoredPlaintext asserts that the backend holds exactly what the client
// sent, with nothing added in the proxy's own metadata namespace.
func assertStoredPlaintext(t *testing.T, minioClient *s3.Client, bucket, key string, plaintext []byte) {
	t.Helper()

	stored, metadata := storedObject(t, minioClient, bucket, key)
	assertDataHashesEqual(t, plaintext, stored, "the exit provider must store the plaintext unchanged")
	for name := range metadata {
		assert.False(t, strings.HasPrefix(name, "s3ep-"),
			"the exit provider must write no s3ep-* metadata, found %s", name)
	}
}

// TestExitProvider_ReadsBackAnEncryptedObject is the point of the exit
// provider: an object written through the encrypting proxy is still readable
// after the switch, and objects written after the switch are plaintext. This
// covers the single-request write path on both sides.
func TestExitProvider_ReadsBackAnEncryptedObject(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	EnsureMinIOAvailable(t)

	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	const (
		bucketName     = "exit-readback-single"
		encryptedKey   = "written-before-the-switch.bin"
		plaintextKey   = "written-after-the-switch.bin"
		rangeFrom      = 1000
		rangeLastIndex = 1999
	)
	payload := randomPayload(t, 64*1024)

	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	// Before the switch: the encrypting proxy writes the object.
	t.Log("Step 1: writing through the aes proxy")
	aesProxy := StartAESProviderProxyInstance(t)
	require.Less(t, int64(len(payload)), aesProxy.segmentSize,
		"this payload must take the single-request write path")
	_, err = aesProxy.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(encryptedKey),
		Body:     bytes.NewReader(payload),
		Metadata: map[string]string{"written-by": "aes"},
	})
	require.NoError(t, err, "failed to write through the aes proxy")
	aesProxy.Stop()

	assertStoredEncrypted(t, minioClient, bucketName, encryptedKey, payload)

	// The switch. Same backend, same bucket, exit provider active, the key that
	// wrapped the object above still registered.
	t.Log("Step 2: switching to the exit proxy")
	exitProxy := StartExitProviderProxyInstance(t)
	defer exitProxy.Stop()

	t.Log("Step 3: the exit proxy decrypts what the aes proxy wrote")
	assertDataHashesEqual(t, payload, getViaClient(t, exitProxy.client, bucketName, encryptedKey),
		"the exit provider must decrypt an object this proxy encrypted earlier")

	head, err := exitProxy.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(encryptedKey),
	})
	require.NoError(t, err, "HEAD of the encrypted object")
	assert.Equal(t, int64(len(payload)), aws.ToInt64(head.ContentLength),
		"HEAD reports the plaintext length of an encrypted object")
	assert.Equal(t, "aes", head.Metadata["written-by"], "client metadata survives the switch")
	for name := range head.Metadata {
		assert.False(t, strings.HasPrefix(name, "s3ep-"),
			"the proxy's own metadata must not reach the client, found %s", name)
	}

	// A ranged read of the encrypted object. Under the exit provider this is the
	// one request that costs an extra HEAD, because the proxy has to know whether
	// the object is one of its own before it can choose the stored window.
	t.Log("Step 4: ranged read of the encrypted object")
	ranged, err := exitProxy.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(encryptedKey),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", rangeFrom, rangeLastIndex)),
	})
	require.NoError(t, err, "ranged GET of the encrypted object")
	rangedData, err := io.ReadAll(ranged.Body)
	require.NoError(t, err)
	ranged.Body.Close()
	assertDataHashesEqual(t, payload[rangeFrom:rangeLastIndex+1], rangedData,
		"a ranged read of an encrypted object must return that window of the plaintext")

	// After the switch: a new object is stored as it was sent.
	t.Log("Step 5: writing a new object through the exit proxy")
	fresh := randomPayload(t, 32*1024)
	require.Less(t, int64(len(fresh)), exitProxy.segmentSize,
		"this payload must take the single-request write path")
	_, err = exitProxy.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(plaintextKey),
		Body:     bytes.NewReader(fresh),
		Metadata: map[string]string{"written-by": "exit"},
	})
	require.NoError(t, err, "failed to write through the exit proxy")

	assertStoredPlaintext(t, minioClient, bucketName, plaintextKey, fresh)
	assertDataHashesEqual(t, fresh, getViaClient(t, exitProxy.client, bucketName, plaintextKey),
		"the exit provider must serve back what it stored")

	// A ranged read of the plain object takes the pass-through arm instead.
	plainRange, err := exitProxy.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(plaintextKey),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", rangeFrom, rangeLastIndex)),
	})
	require.NoError(t, err, "ranged GET of the plain object")
	plainRangeData, err := io.ReadAll(plainRange.Body)
	require.NoError(t, err)
	plainRange.Body.Close()
	assertDataHashesEqual(t, fresh[rangeFrom:rangeLastIndex+1], plainRangeData,
		"a ranged read of a plain object must return that window verbatim")

	// The listing rule is deliberate and stays: under the exit provider <Size>
	// is the stored size, reported verbatim, for both kinds of object. Inverting
	// the arithmetic would be exact for the encrypted ones and would under-report
	// the plain ones, and a sync client that believes the remote is smaller may
	// upload over it. Over-reporting only costs a re-transfer.
	t.Log("Step 6: the listing reports stored sizes")
	listing, err := exitProxy.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err, "ListObjectsV2 through the exit proxy")

	sizes := map[string]int64{}
	for _, entry := range listing.Contents {
		sizes[aws.ToString(entry.Key)] = aws.ToInt64(entry.Size)
	}
	storedEncrypted, _ := storedObject(t, minioClient, bucketName, encryptedKey)
	assert.Equal(t, int64(len(storedEncrypted)), sizes[encryptedKey],
		"the encrypted object is listed with its stored size, which is larger than its plaintext")
	assert.Equal(t, int64(len(fresh)), sizes[plaintextKey],
		"the plain object is listed with its own size")
}

// TestExitProvider_ReadsBackAMultipartObject repeats the exercise above one
// byte past the segment size, which is what sends both proxies through the
// multipart producer instead of the single PUT. It is a separate write path on
// each side and had to be changed separately.
func TestExitProvider_ReadsBackAMultipartObject(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	EnsureMinIOAvailable(t)

	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	const (
		bucketName   = "exit-readback-multipart"
		encryptedKey = "large-written-before-the-switch.bin"
		plaintextKey = "large-written-after-the-switch.bin"
	)

	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()

	t.Log("Step 1: writing a multi-segment object through the aes proxy")
	aesProxy := StartAESProviderProxyInstance(t)
	// One megabyte past the segment size: two parts, the second one short.
	payload := randomPayload(t, int(aesProxy.segmentSize)+1024*1024)
	require.Greater(t, int64(len(payload)), aesProxy.segmentSize,
		"this payload must take the multipart producer")
	_, err = aesProxy.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(encryptedKey),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err, "failed to write the large object through the aes proxy")
	aesProxy.Stop()

	assertStoredEncrypted(t, minioClient, bucketName, encryptedKey, payload)

	t.Log("Step 2: switching to the exit proxy")
	exitProxy := StartExitProviderProxyInstance(t)
	defer exitProxy.Stop()

	t.Log("Step 3: the exit proxy decrypts the multi-segment object")
	assertDataHashesEqual(t, payload, getViaClient(t, exitProxy.client, bucketName, encryptedKey),
		"the exit provider must decrypt a multi-segment object this proxy encrypted earlier")

	t.Log("Step 4: writing a multi-segment object through the exit proxy")
	fresh := randomPayload(t, int(exitProxy.segmentSize)+1024*1024)
	require.Greater(t, int64(len(fresh)), exitProxy.segmentSize,
		"this payload must take the multipart producer")
	_, err = exitProxy.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(plaintextKey),
		Body:   bytes.NewReader(fresh),
	})
	require.NoError(t, err, "failed to write the large object through the exit proxy")

	assertStoredPlaintext(t, minioClient, bucketName, plaintextKey, fresh)
	assertDataHashesEqual(t, fresh, getViaClient(t, exitProxy.client, bucketName, plaintextKey),
		"the exit provider must serve back the large object it stored")
}

// TestExitProvider_ClientDrivenMultipart covers the third write path: the
// client runs the multipart upload itself. Under the exit provider the proxy
// registers no session and adds nothing to a part, so the object is built from
// the client's own part list and the backend owns the part layout.
func TestExitProvider_ClientDrivenMultipart(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	EnsureMinIOAvailable(t)

	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "MinIO client creation failed")

	const (
		bucketName = "exit-client-multipart"
		objectKey  = "client-driven.bin"
	)

	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	ctx := context.Background()
	exitProxy := StartExitProviderProxyInstance(t)
	defer exitProxy.Stop()

	// S3 exempts only the last part from the 5 MiB minimum.
	parts := [][]byte{randomPayload(t, 5*1024*1024), randomPayload(t, 1024*1024)}

	created, err := exitProxy.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		Metadata: map[string]string{"written-by": "exit-multipart"},
	})
	require.NoError(t, err, "CreateMultipartUpload through the exit proxy")
	uploadID := aws.ToString(created.UploadId)
	require.NotEmpty(t, uploadID, "the backend must return an upload id")

	completed := make([]types.CompletedPart, 0, len(parts))
	for i, part := range parts {
		number := int32(i + 1)
		uploaded, uploadErr := exitProxy.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(bucketName),
			Key:        aws.String(objectKey),
			UploadId:   aws.String(uploadID),
			PartNumber: aws.Int32(number),
			Body:       bytes.NewReader(part),
		})
		require.NoErrorf(t, uploadErr, "UploadPart %d through the exit proxy", number)
		completed = append(completed, types.CompletedPart{
			PartNumber: aws.Int32(number),
			ETag:       uploaded.ETag,
		})
	}

	_, err = exitProxy.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucketName),
		Key:             aws.String(objectKey),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	require.NoError(t, err, "CompleteMultipartUpload through the exit proxy")

	whole := append(append([]byte{}, parts[0]...), parts[1]...)
	assertStoredPlaintext(t, minioClient, bucketName, objectKey, whole)
	assertDataHashesEqual(t, whole, getViaClient(t, exitProxy.client, bucketName, objectKey),
		"the exit provider must serve back the client-assembled object")
}
