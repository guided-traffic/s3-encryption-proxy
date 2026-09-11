//nolint:revive // Mock S3 client methods follow AWS SDK naming conventions
package multipart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// MockS3Backend for testing
type MockS3Backend struct {
	mock.Mock
}

func (m *MockS3Backend) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.UploadPartOutput), args.Error(1)
}

func (m *MockS3Backend) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CompleteMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.AbortMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *MockS3Backend) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

func (m *MockS3Backend) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Backend) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsV2Output), args.Error(1)
}

func (m *MockS3Backend) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
}

func (m *MockS3Backend) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

func (m *MockS3Backend) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadBucketOutput), args.Error(1)
}

// Bucket ACL operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketAclOutput), args.Error(1)
}

// Bucket CORS operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketCorsOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketCorsOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketCorsOutput), args.Error(1)
}

// Bucket configuration operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Backend) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketRequestPaymentOutput), args.Error(1)
}

// Bucket tagging operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketTaggingOutput), args.Error(1)
}

// Bucket notification operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketNotificationConfigurationOutput), args.Error(1)
}

// Bucket lifecycle operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketLifecycleOutput), args.Error(1)
}

// Bucket replication operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketReplicationOutput), args.Error(1)
}

// Bucket website operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketWebsiteOutput), args.Error(1)
}

// Additional operations - stubs for interface compliance
func (m *MockS3Backend) ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsOutput), args.Error(1)
}

// Bucket location operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

// Bucket logging operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketLogging(ctx context.Context, params *s3.PutBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketLoggingOutput), args.Error(1)
}

// Bucket policy operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketPolicy(ctx context.Context, params *s3.PutBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketPolicy(ctx context.Context, params *s3.DeleteBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketPolicyOutput), args.Error(1)
}

// Passthrough operations - stubs for interface compliance
func (m *MockS3Backend) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectTorrentOutput), args.Error(1)
}

func setupMultipartTestEnv(t *testing.T) (*orchestration.Manager, *MockS3Backend, *logrus.Entry, *response.XMLWriter, *response.ErrorWriter, *request.Parser) {
	// Create test configuration with an encrypting provider
	metadataPrefix := "s3ep-"
	testConfig := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     &metadataPrefix,
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=", // Base64 of 32-byte key
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := orchestration.NewManager(testConfig)
	require.NoError(t, err)

	// Create mock S3 client
	mockS3Backend := new(MockS3Backend)

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logEntry := logrus.NewEntry(logger)

	// Create response writers
	xmlWriter := response.NewXMLWriter(logEntry)
	errorWriter := response.NewErrorWriter(logEntry)

	// Create request parser
	requestParser := request.NewParser(logEntry, &config.Config{})

	return encMgr, mockS3Backend, logEntry, xmlWriter, errorWriter, requestParser
}

// storablePartSegments is the smallest part the backend takes in the middle of
// an upload: whole segments, and at or above the 5 MiB minimum.
const storablePartSegments = 80

// alignedPlaintext builds a plaintext of whole segments. Only a part of that
// shape, and no smaller than the backend's minimum, can be stored where it
// lies; anything else is held until Complete.
func alignedPlaintext(segments int) []byte {
	data := make([]byte, segments*dataencryption.SegmentSize)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

func TestCreateHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response
	var captured *s3.CreateMultipartUploadInput
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.CreateMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" && aws.ToString(input.Key) == "test-key"
	})).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create test request
	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test-upload-id")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// The object is readable the moment Complete returns because its metadata is
	// already here: S3 accepts none at Complete, and nothing rewrites the object.
	require.NotNil(t, captured)
	assert.NotEmpty(t, captured.Metadata["s3ep-encrypted-dek"])
	assert.Equal(t, dataencryption.FormatID, captured.Metadata["s3ep-dek-algorithm"])
	assert.NotEmpty(t, captured.Metadata["s3ep-kek-fingerprint"])
	assert.NotEmpty(t, captured.Metadata["s3ep-kek-algorithm"])

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_HandleStandard(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	testData := alignedPlaintext(storablePartSegments)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 response for upload part
	var stored []byte
	var declaredLen int64
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id" &&
			aws.ToInt32(input.PartNumber) == 1
	})).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		declaredLen = aws.ToInt64(input.ContentLength)
		stored, _ = io.ReadAll(input.Body)
	}).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"part-etag-1"`),
	}, nil)

	// Create test request
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id", bytes.NewReader(testData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"part-etag-1"`, w.Header().Get("ETag"))

	// A part covering whole segments is sealed and stored where it lies: one
	// segment of framing on top of the plaintext, and the length is declared
	// exactly, so the backend never has to buffer to find out.
	require.Len(t, stored, storablePartSegments*(dataencryption.SegmentSize+dataencryption.SegmentOverhead))
	assert.Equal(t, int64(len(stored)), declaredLen)
	assert.False(t, bytes.Contains(stored, testData[:64]), "the backend must never see the plaintext")

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_ShortPartIsHeldUntilComplete(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq = mux.SetURLVars(createReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// A part that does not cover whole segments cannot be stored on its own: a
	// chain with a short segment in the middle writes cleanly and never reads.
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader([]byte("a short last part")))
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockS3Backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)

	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_SecondShortPartIsRefused(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq = mux.SetURLVars(createReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	firstReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(make([]byte, 100)))
	firstReq = mux.SetURLVars(firstReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	firstW := httptest.NewRecorder()
	handler.Handle(firstW, firstReq)
	require.Equal(t, http.StatusOK, firstW.Code)

	// Only one part can be last, so only one may be short. Refusing here is what
	// keeps the object from being written in a shape no reader can open.
	secondReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=2&uploadId=test-upload-id",
		bytes.NewReader(make([]byte, 200)))
	secondReq = mux.SetURLVars(secondReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	secondW := httptest.NewRecorder()
	handler.Handle(secondW, secondReq)

	assert.Equal(t, http.StatusBadRequest, secondW.Code)
	assert.Contains(t, secondW.Body.String(), "EntityTooSmall")
	mockS3Backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)

	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 1
	})).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"part-etag-1"`),
	}, nil)

	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(alignedPlaintext(storablePartSegments)))
	uploadReq = mux.SetURLVars(uploadReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	uploadW := httptest.NewRecorder()
	uploadHandler.Handle(uploadW, uploadReq)
	require.Equal(t, http.StatusOK, uploadW.Code)

	// The last part ends inside a segment, so it is held until here and stored
	// now, with the record that closes the object behind it.
	lastPart := []byte("the tail that ends inside a segment")
	lastReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=2&uploadId=test-upload-id",
		bytes.NewReader(lastPart))
	lastReq = mux.SetURLVars(lastReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	lastW := httptest.NewRecorder()
	uploadHandler.Handle(lastW, lastReq)
	require.Equal(t, http.StatusOK, lastW.Code)

	var final []byte
	var finalLen int64
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 2
	})).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		finalLen = aws.ToInt64(input.ContentLength)
		final, _ = io.ReadAll(input.Body)
	}).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"final-etag"`),
	}, nil)

	// Mock S3 responses
	var completed *s3.CompleteMultipartUploadInput
	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.CompleteMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id"
	})).Run(func(args mock.Arguments) {
		completed = args.Get(1).(*s3.CompleteMultipartUploadInput)
	}).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:    aws.String("test-bucket"),
		Key:       aws.String("test-key"),
		ETag:      aws.String(`"complete-etag"`),
		Location:  aws.String("http://test-bucket.s3.amazonaws.com/test-key"),
		VersionId: aws.String("mpu-version"),
	}, nil)

	// The client sends back what each part was answered with. That list is checked
	// against the proxy's part table but is not what the object is built from: the
	// proxy stored these parts and knows what the backend called them.
	requestBody := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>%s</ETag>
		</Part>
		<Part>
			<PartNumber>2</PartNumber>
			<ETag>%s</ETag>
		</Part>
	</CompleteMultipartUpload>`, uploadW.Header().Get("ETag"), lastW.Header().Get("ETag"))

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/xml")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "complete-etag")
	assert.Contains(t, w.Body.String(), "test-bucket")
	assert.Contains(t, w.Body.String(), "test-key")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Nothing rewrites the object after Complete, so the completion is what the
	// client can read and its ETag and version are the ones that count.
	assert.Equal(t, `"complete-etag"`, w.Header().Get("ETag"))
	assert.Equal(t, "mpu-version", w.Header().Get("x-amz-version-id"))
	mockS3Backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)

	// The held part, its own segment framing, and the trailer that closes the
	// object - the one part S3 exempts from its minimum size.
	require.Len(t, final, len(lastPart)+dataencryption.SegmentOverhead+dataencryption.TrailerSize)
	assert.Equal(t, int64(len(final)), finalLen)

	require.NotNil(t, completed)
	require.Len(t, completed.MultipartUpload.Parts, 2)
	assert.Equal(t, int32(1), aws.ToInt32(completed.MultipartUpload.Parts[0].PartNumber))
	assert.Equal(t, "part-etag-1", aws.ToString(completed.MultipartUpload.Parts[0].ETag))
	assert.Equal(t, int32(2), aws.ToInt32(completed.MultipartUpload.Parts[1].PartNumber))
	assert.Equal(t, "final-etag", aws.ToString(completed.MultipartUpload.Parts[1].ETag))

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestAbortHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewAbortHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response
	mockS3Backend.On("AbortMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.AbortMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id"
	})).Return(&s3.AbortMultipartUploadOutput{}, nil)

	// Create test request
	req := httptest.NewRequest("DELETE", "/test-bucket/test-key?uploadId=test-upload-id", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_HandleStreaming(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	testData := alignedPlaintext(storablePartSegments)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 response for upload part
	var capturedUpload *s3.UploadPartInput
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id" &&
			aws.ToInt32(input.PartNumber) == 1
	})).Run(func(args mock.Arguments) {
		capturedUpload = args.Get(1).(*s3.UploadPartInput)
	}).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"streaming-part-etag-1"`),
	}, nil)

	// Create test request with streaming enabled (larger data triggers streaming)
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id", bytes.NewReader(testData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
	req.Header.Set("Transfer-Encoding", "chunked") // This triggers streaming path
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler - this should take the streaming path due to Transfer-Encoding
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"streaming-part-etag-1"`, w.Header().Get("ETag"))

	// The part body sent to the backend is ciphertext, so the client digest of the
	// plaintext part must not travel with it.
	require.NotNil(t, capturedUpload)
	assert.Nil(t, capturedUpload.ContentMD5, "client Content-MD5 must not reach the backend")

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestMultipartHandlers_Integration(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handlers
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	completeHandler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Two whole segments, then a tail that ends inside one: the layout that
	// exercises both the part stored where it lies and the part held for Complete.
	firstPart := alignedPlaintext(2 * storablePartSegments)
	lastPart := []byte("the tail that ends inside a segment")
	plaintext := append(append([]byte{}, firstPart...), lastPart...)

	// Mock S3 responses for full flow
	var objectMetadata map[string]string
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		objectMetadata = args.Get(1).(*s3.CreateMultipartUploadInput).Metadata
	}).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("integration-upload-id"),
	}, nil)

	// The parts as the backend stores them, in the order the object is assembled from.
	storedParts := make(map[int][]byte)
	mockS3Backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		body, err := io.ReadAll(input.Body)
		require.NoError(t, err)
		require.Equal(t, int64(len(body)), aws.ToInt64(input.ContentLength))
		storedParts[int(aws.ToInt32(input.PartNumber))] = body
	}).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"integration-part-etag"`),
	}, nil)

	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		ETag:     aws.String(`"integration-complete-etag"`),
		Location: aws.String("http://test-bucket.s3.amazonaws.com/test-key"),
	}, nil)

	// Step 1: Create multipart upload
	req1 := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req1.Header.Set("Content-Type", "application/octet-stream")
	req1 = mux.SetURLVars(req1, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w1 := httptest.NewRecorder()
	createHandler.Handle(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Contains(t, w1.Body.String(), "integration-upload-id")

	// Step 2: Upload parts
	req2 := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=integration-upload-id", bytes.NewReader(firstPart))
	req2.Header.Set("Content-Length", fmt.Sprintf("%d", len(firstPart)))
	req2 = mux.SetURLVars(req2, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w2 := httptest.NewRecorder()
	uploadHandler.Handle(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, `"integration-part-etag"`, w2.Header().Get("ETag"))

	req2b := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=2&uploadId=integration-upload-id", bytes.NewReader(lastPart))
	req2b.Header.Set("Content-Length", fmt.Sprintf("%d", len(lastPart)))
	req2b = mux.SetURLVars(req2b, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w2b := httptest.NewRecorder()
	uploadHandler.Handle(w2b, req2b)

	assert.Equal(t, http.StatusOK, w2b.Code)

	// Step 3: Complete multipart upload
	requestBody := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>%s</ETag>
		</Part>
		<Part>
			<PartNumber>2</PartNumber>
			<ETag>%s</ETag>
		</Part>
	</CompleteMultipartUpload>`, w2.Header().Get("ETag"), w2b.Header().Get("ETag"))

	req3 := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=integration-upload-id", strings.NewReader(requestBody))
	req3.Header.Set("Content-Type", "application/xml")
	req3 = mux.SetURLVars(req3, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w3 := httptest.NewRecorder()
	completeHandler.Handle(w3, req3)

	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Contains(t, w3.Body.String(), "integration-complete-etag")

	// What the backend now holds has to be exactly the object the metadata from
	// CreateMultipartUpload describes: the parts in order form one chain, and the
	// trailer at its end is what proves nothing was dropped.
	require.Len(t, storedParts, 2)
	object := append(append([]byte{}, storedParts[1]...), storedParts[2]...)

	expectedLen, err := dataencryption.CiphertextSize(int64(len(plaintext)))
	require.NoError(t, err)
	assert.Equal(t, expectedLen, int64(len(object)))

	reader, err := encMgr.OpenSegmented("test-key", objectMetadata, bytes.NewReader(object))
	require.NoError(t, err)
	defer reader.Close()
	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(plaintext), sha256.Sum256(decrypted))

	// Verify all mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_Handle_FinalPartFailure(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 1
	})).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-etag-1"`)}, nil)

	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(alignedPlaintext(storablePartSegments)))
	uploadReq = mux.SetURLVars(uploadReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	uploadW := httptest.NewRecorder()
	uploadHandler.Handle(uploadW, uploadReq)
	require.Equal(t, http.StatusOK, uploadW.Code)

	// The trailer is the record that closes the object - THIS FAILS. Without it
	// the parts are a chain no reader can open, so the upload must not complete.
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 2
	})).Return((*s3.UploadPartOutput)(nil), fmt.Errorf("connection reset by peer"))

	// The parts are removed from the backend rather than left behind for the
	// bucket's lifecycle rules to find.
	mockS3Backend.On("AbortMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.AbortMultipartUploadInput) bool {
		return aws.ToString(input.UploadId) == "test-upload-id"
	})).Return(&s3.AbortMultipartUploadOutput{}, nil)

	// Create test request body
	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"part-etag-1"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/xml")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response - the upload must not be reported as successful when the
	// object cannot be closed
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "Successfully completed")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
	mockS3Backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

// hostileName holds the characters an S3 key may legitimately contain and that
// break a concatenated XML document: & and < end the document early, and the
// trailing markup is what an unescaped body would let a client inject.
const hostileName = `a&b<c>"d"</Key><Injected/>`

// initiateResultDoc mirrors the InitiateMultipartUploadResult response body.
type initiateResultDoc struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// listPartsResultDoc mirrors the ListPartsResult response body.
type listPartsResultDoc struct {
	XMLName  xml.Name `xml:"ListPartsResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
	MaxParts int      `xml:"MaxParts"`
}

// completeResultDoc mirrors the CompleteMultipartUploadResult response body.
type completeResultDoc struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// contextState records how a backend call saw its context at the moment of the
// call. The handler cancels its cleanup context on return, so the state has to be
// captured inside the mock rather than read afterwards.
type contextState struct {
	called      bool
	err         error
	hasDeadline bool
}

func (c *contextState) record(args mock.Arguments) {
	ctx := args.Get(0).(context.Context)
	c.called = true
	c.err = ctx.Err()
	_, c.hasDeadline = ctx.Deadline()
}

func assertDetachedContext(t *testing.T, c *contextState, what string) {
	t.Helper()
	require.True(t, c.called, what+" must still reach the backend")
	assert.NoError(t, c.err, what+" must not run on the cancelled request context")
	assert.True(t, c.hasDeadline, what+" must be bounded by the cleanup timeout")
}

func TestCreateHandler_HostileKeyStaysWellFormedXML(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	bucket := "bucket" + hostileName
	key := "key" + hostileName
	uploadID := "upload" + hostileName

	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}, nil)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": bucket,
		"key":    key,
	})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// A body the client cannot parse makes it retry, and every retry creates a
	// backend upload it can neither complete nor abort.
	var doc initiateResultDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "response body must be well-formed XML")
	assert.Equal(t, bucket, doc.Bucket)
	assert.Equal(t, key, doc.Key)
	assert.Equal(t, uploadID, doc.UploadID)
	assert.NotContains(t, w.Body.String(), "<Injected/>")

	mockS3Backend.AssertExpectations(t)
}

func TestCreateHandler_ForwardsUserMetadata(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	var captured *s3.CreateMultipartUploadInput
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req.Header.Set("X-Amz-Meta-Backup-Name", "velero-backup")
	req.Header.Set("X-Amz-Meta-S3ep-Encrypted-Dek", "injected")
	req.Header.Set("Cache-Control", "max-age=99")
	req.Header.Set("Content-Disposition", `attachment; filename="x.txt"`)
	req.Header.Set("Content-Language", "de-DE")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "velero-backup", captured.Metadata["backup-name"], "user metadata must survive a multipart upload")
	// The proxy's own key is there, and it is the one the proxy wrote: a client
	// value under that name would make the object unreadable.
	assert.NotEqual(t, "injected", captured.Metadata["s3ep-encrypted-dek"], "a client must not be able to inject encryption metadata")
	assert.Equal(t, "max-age=99", aws.ToString(captured.CacheControl))
	assert.Equal(t, `attachment; filename="x.txt"`, aws.ToString(captured.ContentDisposition))
	assert.Equal(t, "de-DE", aws.ToString(captured.ContentLanguage))

	mockS3Backend.AssertExpectations(t)
}

func TestAbortHandler_AbortSurvivesCancelledRequestContext(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewAbortHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	abortCall := &contextState{}
	mockS3Backend.On("AbortMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.AbortMultipartUploadInput) bool {
		return aws.ToString(input.UploadId) == "test-upload-id"
	})).Run(abortCall.record).Return(&s3.AbortMultipartUploadOutput{}, nil)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key?uploadId=test-upload-id", nil)
	reqCtx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(reqCtx)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assertDetachedContext(t, abortCall, "the abort the client asked for")

	mockS3Backend.AssertExpectations(t)
}

func TestListHandler_HandleListParts_HostileKeyStaysWellFormedXML(t *testing.T) {
	_, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewListHandler(mockS3Backend, logger, xmlWriter, errorWriter, requestParser)

	bucket := "bucket" + hostileName
	key := "key" + hostileName
	uploadID := "upload" + hostileName

	req := httptest.NewRequest("GET", "/test-bucket/test-key?uploadId="+url.QueryEscape(uploadID), nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": bucket,
		"key":    key,
	})

	w := httptest.NewRecorder()
	handler.HandleListParts(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var doc listPartsResultDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "response body must be well-formed XML")
	assert.Equal(t, bucket, doc.Bucket)
	assert.Equal(t, key, doc.Key)
	assert.Equal(t, uploadID, doc.UploadID)
	assert.Equal(t, 1000, doc.MaxParts)
	assert.NotContains(t, w.Body.String(), "<Injected/>")

	// The zero-valued elements must keep rendering; a decoded struct cannot tell
	// an absent element from a present one holding the zero value.
	assert.Contains(t, w.Body.String(), "<PartNumberMarker>0</PartNumberMarker>")
	assert.Contains(t, w.Body.String(), "<NextPartNumberMarker>0</NextPartNumberMarker>")
	assert.Contains(t, w.Body.String(), "<IsTruncated>false</IsTruncated>")
}

func TestCompleteHandler_HostileKeyStaysWellFormedXML(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	bucket := "bucket" + hostileName
	key := "key" + hostileName

	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": bucket,
		"key":    key,
	})
	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	mockS3Backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"part-etag-1"`),
	}, nil)

	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(alignedPlaintext(storablePartSegments)))
	uploadReq = mux.SetURLVars(uploadReq, map[string]string{"bucket": bucket, "key": key})
	uploadW := httptest.NewRecorder()
	uploadHandler.Handle(uploadW, uploadReq)
	require.Equal(t, http.StatusOK, uploadW.Code)

	// A backend Location routinely carries & in its query string, so this site is
	// malformed in normal operation, not only under attack.
	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		ETag:     aws.String(`"complete-etag"`),
		Location: aws.String("https://minio:9000/bucket/key?a=1&b=2"),
	}, nil)

	// The ETag is entity-encoded exactly as aws-sdk-go-v2 sends it; encoding/xml
	// resolves it, so the body needs no pre-decoding of its own.
	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>&#34;part-etag-1&#34;</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req = mux.SetURLVars(req, map[string]string{
		"bucket": bucket,
		"key":    key,
	})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var doc completeResultDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "response body must be well-formed XML")
	assert.Equal(t, bucket, doc.Bucket)
	assert.Equal(t, key, doc.Key)
	assert.Equal(t, `"complete-etag"`, doc.ETag)
	assert.NotContains(t, w.Body.String(), "<Injected/>")

	// The backend endpoint must not be reflected to the client.
	assert.Equal(t, "http://example.com/test-bucket/test-key", doc.Location)
	assert.NotContains(t, w.Body.String(), "minio:9000")

	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_StoredAttributesNeedNoSelfCopy(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	var created *s3.CreateMultipartUploadInput
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "text/plain")
	createReq.Header.Set("Content-Encoding", "gzip")
	createReq.Header.Set("Cache-Control", "max-age=99")
	createReq.Header.Set("Content-Disposition", `attachment; filename="x.txt"`)
	createReq.Header.Set("Content-Language", "de")
	createReq.Header.Set("X-Amz-Meta-Backup-Name", "velero-backup")
	createReq = mux.SetURLVars(createReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	mockS3Backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"part-etag-1"`),
	}, nil)

	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(alignedPlaintext(storablePartSegments)))
	uploadReq = mux.SetURLVars(uploadReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	uploadW := httptest.NewRecorder()
	uploadHandler.Handle(uploadW, uploadReq)
	require.Equal(t, http.StatusOK, uploadW.Code)

	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CompleteMultipartUploadOutput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		ETag:   aws.String(`"complete-etag"`),
	}, nil)

	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"part-etag-1"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})

	w := httptest.NewRecorder()
	handler.Handle(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Everything the client asked for is stored by CreateMultipartUpload, and the
	// encryption metadata is complete there too. That is what makes the rewrite
	// after Complete unnecessary - and a rewrite is what must not happen, because
	// it costs a full server-side copy of the object.
	require.NotNil(t, created)
	assert.Equal(t, "text/plain", aws.ToString(created.ContentType))
	assert.Equal(t, "gzip", aws.ToString(created.ContentEncoding))
	assert.Equal(t, "max-age=99", aws.ToString(created.CacheControl))
	assert.Equal(t, `attachment; filename="x.txt"`, aws.ToString(created.ContentDisposition))
	assert.Equal(t, "de", aws.ToString(created.ContentLanguage))
	assert.Equal(t, "velero-backup", created.Metadata["backup-name"])
	assert.NotEmpty(t, created.Metadata["s3ep-encrypted-dek"])
	assert.Equal(t, dataencryption.FormatID, created.Metadata["s3ep-dek-algorithm"])

	mockS3Backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
	mockS3Backend.AssertNotCalled(t, "HeadObject", mock.Anything, mock.Anything)

	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_AbortSurvivesClientDisconnect(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})
	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 1
	})).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-etag-1"`)}, nil)

	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id",
		bytes.NewReader(alignedPlaintext(storablePartSegments)))
	uploadReq = mux.SetURLVars(uploadReq, map[string]string{"bucket": "test-bucket", "key": "test-key"})
	uploadW := httptest.NewRecorder()
	uploadHandler.Handle(uploadW, uploadReq)
	require.Equal(t, http.StatusOK, uploadW.Code)

	// The client is gone, so the call that would close the object fails with it.
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToInt32(input.PartNumber) == 2
	})).Return((*s3.UploadPartOutput)(nil), context.Canceled)

	abortCall := &contextState{}
	mockS3Backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Run(abortCall.record).Return(&s3.AbortMultipartUploadOutput{}, nil)

	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"part-etag-1"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	reqCtx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(reqCtx)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()
	handler.Handle(w, req)

	// The parts are already at the backend; without this abort they stay there,
	// billed and invisible, for an object that was never completed.
	assertDetachedContext(t, abortCall, "the abort of an upload that cannot be closed")

	mockS3Backend.AssertExpectations(t)
}

// Object tagging, retention and legal hold reach the backend (ADR 0007 D4).
func (m *MockS3Backend) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectLegalHoldOutput), args.Error(1)
}
