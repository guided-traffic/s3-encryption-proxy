package object

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

// Simple test to verify package compiles and basic functionality
func TestHandler_BasicInitialization(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	assert.NotNil(t, handler)
	assert.Equal(t, "s3ep-", handler.metadataPrefix)
}

func TestExtractEncryptionMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name                  string
		metadata              map[string]string
		expectedDEK           string
		expectedHasEncryption bool
		expectedIsStreaming   bool
	}{
		{
			name:                  "No metadata",
			metadata:              nil,
			expectedDEK:           "",
			expectedHasEncryption: false,
			expectedIsStreaming:   false,
		},
		{
			name:                  "No encryption metadata",
			metadata:              map[string]string{"user-key": "user-value"},
			expectedDEK:           "",
			expectedHasEncryption: false,
			expectedIsStreaming:   false,
		},
		{
			name: "AES-GCM encryption",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
				"s3ep-dek-algorithm": "aes-gcm",
			},
			expectedDEK:           "ZW5jcnlwdGVkLWRlaw==",
			expectedHasEncryption: true,
			expectedIsStreaming:   false,
		},
		{
			name: "AES-CTR encryption",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
				"s3ep-dek-algorithm": "aes-ctr",
			},
			expectedDEK:           "ZW5jcnlwdGVkLWRlaw==",
			expectedHasEncryption: true,
			expectedIsStreaming:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dek, hasEncryption, isStreaming := handler.extractEncryptionMetadata(tt.metadata)
			assert.Equal(t, tt.expectedDEK, dek)
			assert.Equal(t, tt.expectedHasEncryption, hasEncryption)
			assert.Equal(t, tt.expectedIsStreaming, isStreaming)
		})
	}
}

func TestCleanMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name     string
		metadata map[string]string
		expected map[string]string
	}{
		{
			name:     "Nil metadata",
			metadata: nil,
			expected: nil,
		},
		{
			name:     "Empty metadata",
			metadata: map[string]string{},
			expected: nil,
		},
		{
			name: "Only encryption metadata",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "value",
				"s3ep-dek-algorithm": "aes-gcm",
			},
			expected: nil,
		},
		{
			name: "Mixed metadata",
			metadata: map[string]string{
				"user-key":           "user-value",
				"s3ep-encrypted-dek": "value",
				"another-user-key":   "another-value",
			},
			expected: map[string]string{
				"user-key":         "user-value",
				"another-user-key": "another-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.cleanMetadata(tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsEncryptionMetadata(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "Encryption metadata",
			key:      "s3ep-encrypted-dek",
			expected: true,
		},
		{
			name:     "Another encryption metadata",
			key:      "s3ep-dek-algorithm",
			expected: true,
		},
		{
			name:     "User metadata",
			key:      "user-key",
			expected: false,
		},
		{
			name:     "Similar but not encryption metadata",
			key:      "s3ep",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isEncryptionMetadata(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSegmentSize(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := &Handler{
		logger:         logger.WithField("component", "object-handler"),
		metadataPrefix: "s3ep-",
	}

	segmentSize := handler.getSegmentSize()
	assert.Equal(t, int64(12*1024*1024), segmentSize) // 12MB default
}

// ---------------------------------------------------------------------------
// Shared helpers for the response and upload tests below.
// ---------------------------------------------------------------------------

func testLogEntry() *logrus.Entry {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	return logger.WithField("component", "object-handler")
}

// newResponseTestHandler builds a handler for the paths that only compose a
// response and never need an encryption manager.
func newResponseTestHandler(backend *MockS3Backend) *Handler {
	entry := testLogEntry()
	return &Handler{
		s3Backend:      backend,
		logger:         entry,
		errorWriter:    response.NewErrorWriter(entry),
		metadataPrefix: "s3ep-",
	}
}

// newEncryptingTestHandler builds a fully wired handler with a real AES provider,
// a 1 KiB multipart segment and a single upload worker, so the auto-multipart
// pipeline is deterministic in a unit test.
func newEncryptingTestHandler(t *testing.T, backend *MockS3Backend) *Handler {
	t.Helper()
	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     &prefix,
			IntegrityVerification: config.HMACVerificationStrict,
			Providers: []config.EncryptionProvider{{
				Alias: "test-aes",
				Type:  "aes",
				Config: map[string]interface{}{
					"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
				},
			}},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 1024
	cfg.Optimizations.MultipartUploadConcurrency = 1
	cfg.Optimizations.StreamingThreshold = 5 * 1024 * 1024

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// assertNoChecksumHeaders fails if the response carries any x-amz-checksum-*
// header. The backend values describe the stored ciphertext while the proxy
// answers with plaintext, and a client configured with
// ResponseChecksumValidation=WhenSupported (the SDK default) validates any
// checksum header it receives. The match is on the prefix, so a checksum
// algorithm added to a later SDK cannot slip past a stale name list.
func assertNoChecksumHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for name := range header {
		assert.Falsef(t, strings.HasPrefix(strings.ToLower(name), "x-amz-checksum"),
			"response must not carry the backend checksum header %s", name)
	}
}

func headerNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// GET / HEAD: versionId forwarding, entity headers, no backend checksums.
// ---------------------------------------------------------------------------

func TestHandleGetObject_VersionIDAndResponseHeaders(t *testing.T) {
	backend := new(MockS3Backend)
	h := newResponseTestHandler(backend)

	payload := []byte("plaintext-body")
	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(&s3.GetObjectOutput{
			Body:               io.NopCloser(bytes.NewReader(payload)),
			ContentLength:      aws.Int64(int64(len(payload))),
			ETag:               aws.String(`"ciphertext-etag"`),
			VersionId:          aws.String("version-42"),
			ContentEncoding:    aws.String("gzip"),
			ContentDisposition: aws.String(`attachment; filename="x.txt"`),
			ContentLanguage:    aws.String("de-DE"),
			CacheControl:       aws.String("max-age=99"),
			ChecksumCRC32:      aws.String("AAAAAA=="),
			ChecksumCRC32C:     aws.String("AAAAAA=="),
			ChecksumSHA1:       aws.String("AAAAAA=="),
			ChecksumSHA256:     aws.String("AAAAAA=="),
			ChecksumType:       types.ChecksumTypeFullObject,
		}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-bucket/test-key?versionId=version-42", nil)
	h.handleGetObject(rr, req, "test-bucket", "test-key")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "version-42", aws.ToString(captured.VersionId), "GET must address the requested version")

	assert.Equal(t, "version-42", rr.Header().Get("x-amz-version-id"))
	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, `attachment; filename="x.txt"`, rr.Header().Get("Content-Disposition"))
	assert.Equal(t, "de-DE", rr.Header().Get("Content-Language"))
	assert.Equal(t, "max-age=99", rr.Header().Get("Cache-Control"))
	assertNoChecksumHeaders(t, rr.Result().Header)
	assert.Equal(t, payload, rr.Body.Bytes())
}

// TestWriteGetObjectResponse_EmitsOnlyTheAllowlist pins the whole emitted header
// set of the single funnel every GET branch passes through. It is a snapshot of
// the GET/HEAD contract, not a ceiling: adding a header here is fine, but it has
// to be a deliberate edit of this list.
func TestWriteGetObjectResponse_EmitsOnlyTheAllowlist(t *testing.T) {
	h := newResponseTestHandler(nil)

	body := []byte("plaintext")
	out := &s3.GetObjectOutput{
		Body:               io.NopCloser(bytes.NewReader(body)),
		ContentType:        aws.String("text/plain"),
		ContentLength:      aws.Int64(int64(len(body))),
		ETag:               aws.String(`"ciphertext-etag"`),
		VersionId:          aws.String("version-42"),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String(`attachment; filename="x.txt"`),
		ContentLanguage:    aws.String("de-DE"),
		CacheControl:       aws.String("max-age=99"),
		LastModified:       aws.Time(time.Unix(0, 0).UTC()),
		Metadata:           map[string]string{"user": "value"},
		ChecksumCRC32:      aws.String("AAAAAA=="),
		ChecksumCRC32C:     aws.String("AAAAAA=="),
		ChecksumCRC64NVME:  aws.String("AAAAAA=="),
		ChecksumSHA1:       aws.String("AAAAAA=="),
		ChecksumSHA256:     aws.String("AAAAAA=="),
		ChecksumType:       types.ChecksumTypeFullObject,
	}

	rr := httptest.NewRecorder()
	h.writeGetObjectResponse(rr, out, true)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{
		"accept-ranges",
		"cache-control",
		"content-disposition",
		"content-encoding",
		"content-language",
		"content-length",
		"content-type",
		"etag",
		"last-modified",
		"x-amz-meta-user",
		"x-amz-version-id",
	}, headerNames(rr.Result().Header))
	assertNoChecksumHeaders(t, rr.Result().Header)
}

func TestHandleHeadObject_VersionID(t *testing.T) {
	backend := new(MockS3Backend)
	h := newResponseTestHandler(backend)

	var captured *s3.HeadObjectInput
	backend.On("HeadObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.HeadObjectInput) }).
		Return(&s3.HeadObjectOutput{
			ETag:           aws.String(`"ciphertext-etag"`),
			VersionId:      aws.String("version-42"),
			ChecksumSHA256: aws.String("AAAAAA=="),
		}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/test-bucket/test-key?versionId=version-42", nil)
	h.handleHeadObject(rr, req, "test-bucket", "test-key")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "version-42", aws.ToString(captured.VersionId), "HEAD must address the requested version")
	assert.Equal(t, "version-42", rr.Header().Get("x-amz-version-id"))
	assertNoChecksumHeaders(t, rr.Result().Header)
}

// ---------------------------------------------------------------------------
// Client checksums never reach the backend.
// ---------------------------------------------------------------------------

func TestPutObjectStreamingReader_ClientContentMD5DoesNotReachBackend(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	payload := bytes.Repeat([]byte("a"), 2048)
	var captured *s3.PutObjectInput
	backend.On("PutObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.PutObjectInput) }).
		Return(&s3.PutObjectOutput{ETag: aws.String(`"stored"`), VersionId: aws.String("version-42")}, nil)

	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(payload))
	req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")

	rr := httptest.NewRecorder()
	h.putObjectStreamingReader(rr, req, "test-bucket", "test-key", nil, "application/octet-stream")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Nil(t, captured.ContentMD5, "the client digest describes the plaintext, the body is ciphertext")
	assert.Empty(t, captured.ChecksumAlgorithm)
	assert.Equal(t, "version-42", rr.Header().Get("x-amz-version-id"))
}

func TestHandleDeleteObjects_ChecksumAndDeleteMarkers(t *testing.T) {
	backend := new(MockS3Backend)
	h := newResponseTestHandler(backend)

	var captured *s3.DeleteObjectsInput
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectsInput) }).
		Return(&s3.DeleteObjectsOutput{
			Deleted: []types.DeletedObject{{
				Key:                   aws.String("test-key"),
				DeleteMarker:          aws.Bool(true),
				DeleteMarkerVersionId: aws.String("marker-7"),
			}},
		}, nil)

	body := `<Delete><Object><Key>test-key</Key></Object></Delete>`
	req := httptest.NewRequest(http.MethodPost, "/test-bucket?delete", strings.NewReader(body))
	req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")

	rr := httptest.NewRecorder()
	h.handleDeleteObjects(rr, req, "test-bucket")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Empty(t, captured.ChecksumAlgorithm,
		"a client Content-MD5 must not select a backend checksum algorithm")

	assert.Contains(t, rr.Body.String(), "<DeleteMarker>true</DeleteMarker>")
	assert.Contains(t, rr.Body.String(), "<DeleteMarkerVersionId>marker-7</DeleteMarkerVersionId>")
}

// ---------------------------------------------------------------------------
// Operations that used to answer 200 for work they did not do.
// ---------------------------------------------------------------------------

func TestUnimplementedObjectOperationsAnswer501(t *testing.T) {
	backend := new(MockS3Backend)
	h := newResponseTestHandler(backend)

	cases := map[string]func(w http.ResponseWriter){
		"legal_hold_get": func(w http.ResponseWriter) {
			h.handleObjectLegalHold(w, httptest.NewRequest(http.MethodGet, "/b/k?legal-hold", nil), "b", "k")
		},
		"legal_hold_put": func(w http.ResponseWriter) {
			h.handleObjectLegalHold(w, httptest.NewRequest(http.MethodPut, "/b/k?legal-hold", strings.NewReader("<LegalHold><Status>OFF</Status></LegalHold>")), "b", "k")
		},
		"retention_get": func(w http.ResponseWriter) {
			h.handleObjectRetention(w, httptest.NewRequest(http.MethodGet, "/b/k?retention", nil), "b", "k")
		},
		"retention_put": func(w http.ResponseWriter) {
			h.handleObjectRetention(w, httptest.NewRequest(http.MethodPut, "/b/k?retention", strings.NewReader("<Retention/>")), "b", "k")
		},
		"select": func(w http.ResponseWriter) {
			h.handleSelectObjectContent(w, httptest.NewRequest(http.MethodPost, "/b/k?select&select-type=2", nil), "b", "k")
		},
		"attributes": func(w http.ResponseWriter) {
			req := httptest.NewRequest(http.MethodGet, "/b/k?attributes", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "b", "key": "k"})
			h.Handle(w, req)
		},
	}

	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			run(rr)
			assert.Equal(t, http.StatusNotImplemented, rr.Code)
			assert.Contains(t, rr.Body.String(), "NotImplemented")
		})
	}

	// None of these may reach the backend: answering for work that was never done
	// is the defect, and applying a legal hold nobody asked for is the worst of it.
	for _, method := range []string{
		"GetObjectLegalHold", "PutObjectLegalHold",
		"GetObjectRetention", "PutObjectRetention",
		"SelectObjectContent", "GetObject",
	} {
		backend.AssertNotCalled(t, method, mock.Anything, mock.Anything)
	}
}

// ---------------------------------------------------------------------------
// Auto-multipart: cleanup that must outlive the request, and the truncation guard.
// ---------------------------------------------------------------------------

func TestPutObjectAutoMultipart_AbortOutlivesClientDisconnect(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)

	body := bytes.Repeat([]byte("x"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(body))
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	// The client vanishes exactly when the first part fails, which is the situation
	// that used to cancel the abort along with the request.
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).
		Return(nil, assert.AnError)

	var aborted bool
	var abortCtxErr error
	var abortHasDeadline bool
	backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			abortCtx := args.Get(0).(context.Context)
			aborted = true
			abortCtxErr = abortCtx.Err()
			_, abortHasDeadline = abortCtx.Deadline()
		}).
		Return(&s3.AbortMultipartUploadOutput{}, nil)

	rr := httptest.NewRecorder()
	h.putObjectAutoMultipart(rr, req, "test-bucket", "test-key", "application/octet-stream")

	require.True(t, aborted, "the abort must reach the backend after a client disconnect")
	assert.NoError(t, abortCtxErr, "the abort must not inherit the cancelled request context")
	assert.True(t, abortHasDeadline, "the detached cleanup context must stay bounded")
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// A body shorter than the declared length is a producer error, not a clean end of
// stream. Committing it stores a truncated object whose HMAC covers exactly what
// was uploaded, so every later integrity check passes.
func TestPutObjectAutoMultipart_ShortBodyAbortsInsteadOfCommitting(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil)
	backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.AbortMultipartUploadOutput{}, nil)
	// The commit path is mocked through to the end on purpose. Without it a
	// regression would surface as an "unexpected call" panic from the mock, which
	// stops being a signal the moment someone adds these expectations to a shared
	// helper. With it, the guard is pinned by the two assertions below: a
	// regression lets the upload run to a clean 200 and they fail saying so.
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"committed-truncated"`)}, nil)
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Return(&s3.CopyObjectOutput{
			CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"committed-truncated"`)},
		}, nil)

	body := bytes.Repeat([]byte("x"), 1000)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(body))
	req.ContentLength = 4096 // the client promised four times what it sent

	rr := httptest.NewRecorder()
	h.putObjectAutoMultipart(rr, req, "test-bucket", "test-key", "application/octet-stream")

	assert.Equal(t, http.StatusInternalServerError, rr.Code,
		"a body shorter than the declared length must fail the upload, not report success")
	backend.AssertCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
}

// The self-copy that attaches the encryption metadata also rewrites the object:
// it must survive the client hanging up, it must restate the entity headers that
// MetadataDirective=REPLACE would otherwise drop, and its ETag and version id are
// the ones the client has to be told about.
func TestPutObjectAutoMultipart_SelfCopyOutlivesRequestAndOwnsETag(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	var createInput *s3.CreateMultipartUploadInput
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createInput = args.Get(1).(*s3.CreateMultipartUploadInput) }).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil)

	body := bytes.Repeat([]byte("x"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(body))
	req.Header.Set("Cache-Control", "max-age=99")
	req.Header.Set("Content-Disposition", `attachment; filename="x.txt"`)
	req.Header.Set("Content-Encoding", "aws-chunked,gzip")
	req.Header.Set("Content-Language", "de-DE")
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	// The client hangs up the moment the object is committed at the backend.
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).
		Return(&s3.CompleteMultipartUploadOutput{
			ETag:      aws.String(`"mpu-etag-1"`),
			VersionId: aws.String("mpu-version"),
		}, nil)

	var copied bool
	var copyCtxErr error
	var copyHasDeadline bool
	var copyInput *s3.CopyObjectInput
	backend.On("CopyObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			copyCtx := args.Get(0).(context.Context)
			copied = true
			copyCtxErr = copyCtx.Err()
			_, copyHasDeadline = copyCtx.Deadline()
			copyInput = args.Get(1).(*s3.CopyObjectInput)
		}).
		Return(&s3.CopyObjectOutput{
			CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
			VersionId:        aws.String("copy-version"),
		}, nil)

	rr := httptest.NewRecorder()
	h.putObjectAutoMultipart(rr, req, "test-bucket", "test-key", "text/plain")

	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, copied, "the metadata self-copy must reach the backend")
	assert.NoError(t, copyCtxErr,
		"the self-copy must not inherit the cancelled request context: without it the object is undecryptable")
	assert.True(t, copyHasDeadline)

	require.NotNil(t, createInput)
	assert.Equal(t, "text/plain", aws.ToString(createInput.ContentType))
	assert.Equal(t, "max-age=99", aws.ToString(createInput.CacheControl))
	assert.Equal(t, `attachment; filename="x.txt"`, aws.ToString(createInput.ContentDisposition))
	assert.Equal(t, "gzip", aws.ToString(createInput.ContentEncoding), "aws-chunked describes the request framing")
	assert.Equal(t, "de-DE", aws.ToString(createInput.ContentLanguage))

	require.NotNil(t, copyInput)
	assert.Equal(t, "text/plain", aws.ToString(copyInput.ContentType),
		"MetadataDirective=REPLACE drops every system header the copy does not restate")
	assert.Equal(t, "max-age=99", aws.ToString(copyInput.CacheControl))
	assert.Equal(t, `attachment; filename="x.txt"`, aws.ToString(copyInput.ContentDisposition))
	assert.Equal(t, "gzip", aws.ToString(copyInput.ContentEncoding))
	assert.Equal(t, "de-DE", aws.ToString(copyInput.ContentLanguage))

	assert.Equal(t, `"copy-etag"`, rr.Header().Get("ETag"),
		"the self-copy rewrote the object, so the ETag from Complete is stale")
	assert.Equal(t, "copy-version", rr.Header().Get("x-amz-version-id"))
	backend.AssertNotCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
}
