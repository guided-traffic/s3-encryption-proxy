package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	s3client "github.com/guided-traffic/s3-encryption-proxy/internal/s3client"
)

func setupTestHandlerServer(t *testing.T) *Server {
	cfg := &config.Config{
		BindAddress:    ":8080",
		TargetEndpoint: "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "testkey",
		SecretKey:      "testsecret",
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	encManager, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	server := &Server{
		s3Client:      &s3client.Client{},
		encryptionMgr: encManager,
		config:        cfg,
		logger:        logrus.WithField("test", true),
	}

	return server
}

func TestHandlerBuildGetObjectInput(t *testing.T) {
	server := setupTestHandlerServer(t)

	req, err := http.NewRequest("GET", "/bucket/key", nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=0-1023")
	req.Header.Set("If-Match", "test-etag")
	req.Header.Set("If-None-Match", "other-etag")
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

	input := server.buildGetObjectInput(req, "test-bucket", "test-key")

	assert.Equal(t, "test-bucket", *input.Bucket)
	assert.Equal(t, "test-key", *input.Key)
	assert.Equal(t, "bytes=0-1023", *input.Range)
	assert.Equal(t, "test-etag", *input.IfMatch)
	assert.Equal(t, "other-etag", *input.IfNoneMatch)
	assert.NotNil(t, input.IfModifiedSince)
	assert.NotNil(t, input.IfUnmodifiedSince)
}

func TestHandlerBuildHeadObjectInput(t *testing.T) {
	server := setupTestHandlerServer(t)

	req, err := http.NewRequest("HEAD", "/bucket/key", nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", "test-etag")
	req.Header.Set("If-Match", "match-etag")
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	req.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

	input := server.buildHeadObjectInput(req, "test-bucket", "test-key")

	assert.Equal(t, "test-bucket", *input.Bucket)
	assert.Equal(t, "test-key", *input.Key)
	assert.Equal(t, "test-etag", *input.IfNoneMatch)
	assert.Equal(t, "match-etag", *input.IfMatch)
	assert.NotNil(t, input.IfModifiedSince)
	assert.NotNil(t, input.IfUnmodifiedSince)
}

func TestHandlerReadRequestBody(t *testing.T) {
	server := setupTestHandlerServer(t)

	testData := "test request body content"
	req, err := http.NewRequest("POST", "/test", strings.NewReader(testData))
	require.NoError(t, err)

	body, err := server.readRequestBody(req, "test-bucket", "test-key")
	require.NoError(t, err)
	assert.Equal(t, []byte(testData), body)
}

func TestHandlerReadRequestBody_Error(t *testing.T) {
	server := setupTestHandlerServer(t)

	req, err := http.NewRequest("POST", "/test", &testErrorReader{})
	require.NoError(t, err)

	_, err = server.readRequestBody(req, "test-bucket", "test-key")
	assert.Error(t, err)
}

type testErrorReader struct{}

func (e *testErrorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestHandlerBuildPutObjectInput(t *testing.T) {
	server := setupTestHandlerServer(t)

	testData := []byte("test content data")
	req, err := http.NewRequest("PUT", "/bucket/key", bytes.NewReader(testData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	input := server.buildPutObjectInput(req, "test-bucket", "test-key", testData)

	assert.Equal(t, "test-bucket", *input.Bucket)
	assert.Equal(t, "test-key", *input.Key)
	assert.Equal(t, int64(len(testData)), *input.ContentLength)
	if input.ContentType != nil {
		assert.Equal(t, "text/plain", *input.ContentType)
	}
}

func TestHandlerSetContentHeaders(t *testing.T) {
	server := setupTestHandlerServer(t)

	rr := httptest.NewRecorder()
	output := &contentHeadersOutput{
		ContentType:        aws.String("text/plain"),
		ContentLength:      aws.Int64(1024),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String("attachment"),
		ContentLanguage:    aws.String("en"),
		CacheControl:       aws.String("max-age=3600"),
		ETag:               aws.String("test-etag"),
		LastModified:       aws.Time(time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)),
		ExpiresString:      aws.String("Wed, 21 Oct 2015 07:28:00 GMT"),
	}

	server.setContentHeaders(rr, output)

	assert.Equal(t, "text/plain", rr.Header().Get("Content-Type"))
	assert.Equal(t, "1024", rr.Header().Get("Content-Length"))
	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, "attachment", rr.Header().Get("Content-Disposition"))
	assert.Equal(t, "en", rr.Header().Get("Content-Language"))
	assert.Equal(t, "max-age=3600", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "test-etag", rr.Header().Get("ETag"))
	assert.Contains(t, rr.Header().Get("Last-Modified"), "Wed, 21 Oct 2015 07:28:00")
	assert.Contains(t, rr.Header().Get("Expires"), "Wed, 21 Oct 2015 07:28:00")
}

func TestHandlerSetGetObjectMetadataHeaders(t *testing.T) {
	server := setupTestHandlerServer(t)

	rr := httptest.NewRecorder()
	output := &s3.GetObjectOutput{
		Metadata: map[string]string{
			"custom-key":  "custom-value",
			"another-key": "another-value",
		},
	}

	server.setGetObjectMetadataHeaders(rr, output)

	assert.Equal(t, "custom-value", rr.Header().Get("x-amz-meta-custom-key"))
	assert.Equal(t, "another-value", rr.Header().Get("x-amz-meta-another-key"))
}

func TestHandlerSetGetObjectS3Headers(t *testing.T) {
	server := setupTestHandlerServer(t)

	rr := httptest.NewRecorder()
	output := &s3.GetObjectOutput{
		AcceptRanges: aws.String("bytes"),
		StorageClass: types.StorageClassStandard,
		VersionId:    aws.String("version123"),
	}

	server.setGetObjectS3Headers(rr, output)

	assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
	assert.Equal(t, "STANDARD", rr.Header().Get("x-amz-storage-class"))
	assert.Equal(t, "version123", rr.Header().Get("x-amz-version-id"))
}

func TestHandlerListObjectsV2ToXML(t *testing.T) {
	server := setupTestHandlerServer(t)

	output := &s3.ListObjectsV2Output{
		Name:        aws.String("test-bucket"),
		Prefix:      aws.String("test/"),
		KeyCount:    aws.Int32(2),
		MaxKeys:     aws.Int32(1000),
		IsTruncated: aws.Bool(false),
		Contents: []types.Object{
			{
				Key:          aws.String("test/file1.txt"),
				Size:         aws.Int64(100),
				ETag:         aws.String(`"etag1"`),
				LastModified: aws.Time(time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)),
				StorageClass: types.ObjectStorageClassStandard,
			},
		},
		CommonPrefixes: []types.CommonPrefix{
			{
				Prefix: aws.String("test/subdir/"),
			},
		},
		ContinuationToken:     aws.String("token123"),
		NextContinuationToken: aws.String("next-token456"),
	}

	xml, err := server.listObjectsV2ToXML(output)
	assert.NoError(t, err)
	assert.Contains(t, xml, "test-bucket")
	assert.Contains(t, xml, "test/")
	assert.Contains(t, xml, "test/file1.txt")
	assert.Contains(t, xml, "test/subdir/")
	assert.Contains(t, xml, "token123")
	assert.Contains(t, xml, "next-token456")
	assert.Contains(t, xml, "2")     // KeyCount
	assert.Contains(t, xml, "false") // IsTruncated
}

func TestHandlerListObjectsV1ToXML(t *testing.T) {
	server := setupTestHandlerServer(t)

	output := &s3.ListObjectsOutput{
		Name:        aws.String("test-bucket"),
		Prefix:      aws.String("test/"),
		MaxKeys:     aws.Int32(1000),
		IsTruncated: aws.Bool(true),
		Marker:      aws.String("marker123"),
		NextMarker:  aws.String("next-marker456"),
		Contents: []types.Object{
			{
				Key:          aws.String("test/file1.txt"),
				Size:         aws.Int64(200),
				ETag:         aws.String(`"etag2"`),
				LastModified: aws.Time(time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)),
				StorageClass: types.ObjectStorageClassStandard,
			},
		},
		CommonPrefixes: []types.CommonPrefix{
			{
				Prefix: aws.String("test/subdir/"),
			},
		},
	}

	xml, err := server.listObjectsV1ToXML(output)
	assert.NoError(t, err)
	assert.Contains(t, xml, "test-bucket")
	assert.Contains(t, xml, "test/")
	assert.Contains(t, xml, "test/file1.txt")
	assert.Contains(t, xml, "test/subdir/")
	assert.Contains(t, xml, "marker123")
	assert.Contains(t, xml, "next-marker456")
	assert.Contains(t, xml, "true") // IsTruncated
}
