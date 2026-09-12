//go:build conformance

// The file name carries the order. Go registers a package's tests in the order
// its files are compiled, which is their sorted file name, and runs them in that
// order: this file sorts first so the corpus is checked before anything reads
// it, and z_cost_test.go sorts last so the cost guards audit the run that just
// happened rather than the one before it.

package conformance

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSeed writes the corpus, once.
//
// It is idempotent by size: an object that is already there with the right
// plaintext length is left alone, and nothing is written. That is the whole cost
// model of this suite — the paid backend bills a written byte for ninety days
// and refunds nothing when it is deleted, so the only lever is not writing it
// twice. A second seeding run against a seeded bucket costs zero.
//
// It skips unless S3EP_CONFORMANCE_SEED=1, so a normal run cannot write by
// accident, and it writes through the budget, so a payload someone grows by a
// factor of a hundred fails here instead of on the invoice.
func TestSeed(t *testing.T) {
	if !IsSeedRun() {
		t.Skip("not a seeding run: set S3EP_CONFORMANCE_SEED=1 to write the corpus")
	}

	ctx, cancel := Context(t)
	defer cancel()

	proxy := ProxyClient(t)
	budget := NewBudget()

	// A bucket that is already there is never created, and creation is only
	// attempted when it is genuinely missing. That ordering matters against the
	// paid backend: its credential deliberately carries no s3:CreateBucket
	// (ADR 0027 D9, and a suite that could create buckets could create them in
	// the wrong place), so an unconditional CreateBucket fails a seed that had
	// nothing to do. On a throwaway stack the bucket is missing and gets made.
	if _, err := proxy.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(Bucket),
	}); err != nil {
		if _, createErr := proxy.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(Bucket),
		}); createErr != nil && !bucketAlreadyThere(createErr) {
			require.NoError(t, createErr,
				"%s does not exist and this credential may not create it. "+
					"Create it once, by hand: the suite never creates or deletes the bucket "+
					"it is pointed at.", Bucket)
		}
	}

	written, skipped := 0, 0

	seed := func(key string, size int64) {
		full := Key(key)
		body := Content(key, size)

		if head, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(Bucket),
			Key:    aws.String(full),
		}); err == nil {
			// The proxy reports the plaintext length, which is what the corpus
			// is defined in, so this compares like with like.
			if aws.ToInt64(head.ContentLength) == size {
				skipped++
				t.Logf("present, not rewritten: %s (%d bytes)", full, size)
				return
			}
			t.Fatalf("%s exists with %d bytes, the corpus says %d. Refusing to rewrite it: "+
				"delete it deliberately if the corpus definition changed.",
				full, aws.ToInt64(head.ContentLength), size)
		}

		budget.Authorize(t, full, size)
		_, err := proxy.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(Bucket),
			Key:           aws.String(full),
			Body:          bytes.NewReader(body),
			ContentLength: aws.Int64(size),
		})
		require.NoError(t, err, "seeding %s", full)
		written++
		t.Logf("written: %s (%d bytes)", full, size)
	}

	t.Run("corpus", func(t *testing.T) {
		for _, obj := range Corpus {
			// mpu-client is seeded through the client-driven multipart path on
			// purpose: seeding it with a plain PUT would store the same bytes
			// through the producer and leave that path untested.
			if obj.Key == "mpu-client" {
				seedClientMultipart(t, proxy, budget, obj)
				continue
			}
			seed(obj.Key, obj.Size)
		}
	})

	t.Run("listing_corpus", func(t *testing.T) {
		for i := 0; i < ListCorpusSize; i++ {
			seed(ListKey(i), 1)
		}
	})

	t.Logf("seed complete against %s: %d objects written, %d already present, %d bytes of a %d byte budget",
		BackendName, written, skipped, budget.Spent(), SeedBudgetBytes)
}

// seedClientMultipart writes one corpus object through CreateMultipartUpload so
// the client-driven path is exercised with a real two-part layout: a first part
// at the S3 minimum, which the proxy stores where it lies, and a short last part,
// which it buffers and seals with the trailer behind it.
//
// The upload is aborted on every failure path. An incomplete multipart upload
// holds its parts as billed storage until it is aborted, and on a backend with a
// ninety-day minimum a leaked one is a charge that outlives the branch.
func seedClientMultipart(t *testing.T, proxy *s3.Client, budget *Budget, obj CorpusObject) {
	t.Helper()
	ctx, cancel := Context(t)
	defer cancel()

	full := Key(obj.Key)
	if head, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(Bucket),
		Key:    aws.String(full),
	}); err == nil && aws.ToInt64(head.ContentLength) == obj.Size {
		t.Logf("present, not rewritten: %s (%d bytes)", full, obj.Size)
		return
	}

	budget.Authorize(t, full, obj.Size)
	body := Content(obj.Key, obj.Size)

	create, err := proxy.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(Bucket),
		Key:    aws.String(full),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	completed := false
	t.Cleanup(func() {
		if completed {
			return
		}
		abortCtx, abortCancel := Context(t)
		defer abortCancel()
		_, abortErr := proxy.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(Bucket),
			Key:      aws.String(full),
			UploadId: aws.String(uploadID),
		})
		if abortErr != nil {
			t.Errorf("the multipart upload of %s was left open and its parts stay billed: %v",
				full, abortErr)
		}
	})

	const firstPart = 5 << 20
	parts := [][]byte{body[:firstPart], body[firstPart:]}
	done := make([]types.CompletedPart, 0, len(parts))

	for i, part := range parts {
		number := int32(i + 1) // #nosec G115 - two parts
		out, upErr := proxy.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(Bucket),
			Key:           aws.String(full),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(number),
			Body:          bytes.NewReader(part),
			ContentLength: aws.Int64(int64(len(part))),
		})
		require.NoError(t, upErr, "uploading part %d of %s", number, full)
		done = append(done, types.CompletedPart{
			PartNumber: aws.Int32(number),
			ETag:       out.ETag,
		})
	}

	_, err = proxy.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(Bucket),
		Key:             aws.String(full),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: done},
	})
	require.NoError(t, err)
	completed = true
	t.Logf("written through client-driven multipart: %s (%d bytes, 2 parts)", full, obj.Size)
}

// TestCorpusStillExercisesEveryWritePath couples the corpus to the proxy's own
// part threshold. "mpu-producer" is the only object that makes a single PUT
// become the proxy's internal multipart upload, and it does so only while it is
// larger than the configured streaming_segment_size — which the run script sets
// and exports. Without this, raising that value or shrinking the object leaves
// the producer path untested and every assertion green.
func TestCorpusStillExercisesEveryWritePath(t *testing.T) {
	threshold := SegmentSizeFromEnv()

	var producer, clientDriven *CorpusObject
	for i := range Corpus {
		switch Corpus[i].Key {
		case "mpu-producer":
			producer = &Corpus[i]
		case "mpu-client":
			clientDriven = &Corpus[i]
		}
	}
	require.NotNil(t, producer, "the corpus no longer has an object for the internal producer")
	require.NotNil(t, clientDriven, "the corpus no longer has an object for a client-driven upload")

	assert.Greater(t, producer.Size, threshold,
		"%q is %d bytes and streaming_segment_size is %d: this run sends it as one request "+
			"and the internal producer is exercised by nothing",
		producer.Key, producer.Size, threshold)
	assert.GreaterOrEqual(t, clientDriven.Size, int64(5<<20),
		"a client-driven upload needs a first part at or above the S3 minimum")
}

// TestSeedIsComplete fails a read-only run whose corpus is missing, instead of
// letting every later test fail one by one with NoSuchKey.
func TestSeedIsComplete(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	var missing []string
	for _, obj := range Corpus {
		head, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(Bucket),
			Key:    aws.String(Key(obj.Key)),
		})
		if err != nil {
			missing = append(missing, obj.Key)
			continue
		}
		assert.Equal(t, obj.Size, aws.ToInt64(head.ContentLength),
			"%s: the proxy reports the plaintext length, and the corpus defines it", obj.Key)
	}

	if len(missing) > 0 {
		t.Fatalf("the corpus is not seeded in %s (missing: %v). "+
			"Run `make test-conformance-seed` once against this backend.", Bucket, missing)
	}
}

// bucketAlreadyThere reports the two codes S3 uses for a bucket that exists. On
// the paid backend this is the normal answer: the operator created the bucket
// once, and the suite never creates or deletes it.
func bucketAlreadyThere(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "BucketAlreadyOwnedByYou", "BucketAlreadyExists":
		return true
	}
	return false
}
