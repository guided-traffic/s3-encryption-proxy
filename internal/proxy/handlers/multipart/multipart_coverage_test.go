package multipart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	MpuBucket   = "cov-bucket"
	MpuKey      = "cov/key.bin"
	MpuUploadID = "cov-upload-id"
	// MpuAESKey is a base64 256-bit key; the value only has to be stable.
	MpuAESKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
)

// MpuEnv bundles the collaborators every multipart sub-handler is built from.
type MpuEnv struct {
	enc     *orchestration.Manager
	backend *MockS3Backend
	logger  *logrus.Entry
	xmlW    *response.XMLWriter
	errW    *response.ErrorWriter
	parser  *request.Parser
	cfg     *config.Config
}

// MpuNewEnv builds an environment whose active provider encrypts (AES envelope,
// HMAC on), which is the configuration a production deployment runs.
func MpuNewEnv(t *testing.T) *MpuEnv {
	t.Helper()
	return MpuNewEnvWithProvider(t, config.EncryptionProvider{
		Alias:  "cov-aes",
		Type:   "aes",
		Config: map[string]interface{}{"aes_key": MpuAESKey},
	}, "strict")
}

// MpuNewNoneEnv builds an environment on the pass-through provider, which is the
// only configuration that produces no encryption metadata at completion time.
func MpuNewNoneEnv(t *testing.T) *MpuEnv {
	t.Helper()
	return MpuNewEnvWithProvider(t, config.EncryptionProvider{
		Alias: "cov-none",
		Type:  "none",
	}, "off")
}

func MpuNewEnvWithProvider(t *testing.T, provider config.EncryptionProvider, integrity string) *MpuEnv {
	t.Helper()

	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: provider.Alias,
			MetadataKeyPrefix:     &prefix,
			IntegrityVerification: integrity,
			Providers:             []config.EncryptionProvider{provider},
		},
	}

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)

	// Quiet: these tests drive the debug-heavy handlers dozens of times.
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.ErrorLevel)
	entry := logrus.NewEntry(logger)

	return &MpuEnv{
		enc:     encMgr,
		backend: new(MockS3Backend),
		logger:  entry,
		xmlW:    response.NewXMLWriter(entry),
		errW:    response.NewErrorWriter(entry),
		parser:  request.NewParser(entry, cfg),
		cfg:     cfg,
	}
}

func (e *MpuEnv) create() *CreateHandler {
	return NewCreateHandler(e.backend, e.enc, e.logger, e.xmlW, e.errW, e.parser)
}

func (e *MpuEnv) upload() *UploadHandler {
	return NewUploadHandler(e.backend, e.enc, e.logger, e.xmlW, e.errW, e.parser)
}

func (e *MpuEnv) complete() *CompleteHandler {
	return NewCompleteHandler(e.backend, e.enc, e.logger, e.xmlW, e.errW, e.parser)
}

func (e *MpuEnv) abort() *AbortHandler {
	return NewAbortHandler(e.backend, e.enc, e.logger, e.xmlW, e.errW, e.parser)
}

func (e *MpuEnv) list() *ListHandler {
	return NewListHandler(e.backend, e.logger, e.xmlW, e.errW, e.parser)
}

// MpuVars attaches the mux path variables the handlers read.
func MpuVars(r *http.Request) *http.Request {
	return mux.SetURLVars(r, map[string]string{"bucket": MpuBucket, "key": MpuKey})
}

// MpuInitiate runs a real CreateMultipartUpload so that a live encryption session
// exists for uploadID, exactly as a client would establish it.
func (e *MpuEnv) MpuInitiate(t *testing.T, uploadID string) {
	t.Helper()
	e.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String(MpuBucket),
		Key:      aws.String(MpuKey),
		UploadId: aws.String(uploadID),
	}, nil).Once()

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	w := httptest.NewRecorder()
	e.create().Handle(w, req)
	require.Equal(t, http.StatusOK, w.Code, "test fixture: CreateMultipartUpload must succeed")
}

// MpuUploadPart drives one real part upload through the handler.
func (e *MpuEnv) MpuUploadPart(t *testing.T, uploadID string, partNumber int, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", MpuBucket, MpuKey, partNumber, uploadID)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body)))
	w := httptest.NewRecorder()
	e.upload().Handle(w, req)
	return w
}

// MpuCompleteBody renders a CompleteMultipartUpload document for the given parts.
func MpuCompleteBody(parts ...int) string {
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>\"etag-%d\"</ETag></Part>", p, p)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

// MpuErrorDoc mirrors the S3 <Error> document every failing request must answer with.
type MpuErrorDoc struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource"`
}

func MpuParseError(t *testing.T, body []byte) MpuErrorDoc {
	t.Helper()
	var doc MpuErrorDoc
	require.NoError(t, xml.Unmarshal(body, &doc), "error body must be a well-formed S3 <Error> document: %s", body)
	return doc
}

// MpuListPartsDoc mirrors the full ListPartsResult document, <Part> children included.
type MpuListPartsDoc struct {
	XMLName              xml.Name `xml:"ListPartsResult"`
	Bucket               string   `xml:"Bucket"`
	Key                  string   `xml:"Key"`
	UploadID             string   `xml:"UploadId"`
	StorageClass         string   `xml:"StorageClass"`
	PartNumberMarker     int      `xml:"PartNumberMarker"`
	NextPartNumberMarker int      `xml:"NextPartNumberMarker"`
	MaxParts             int      `xml:"MaxParts"`
	IsTruncated          bool     `xml:"IsTruncated"`
	Parts                []struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

// MpuCompleteDoc mirrors the CompleteMultipartUploadResult document.
type MpuCompleteDoc struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// MpuInitiateDoc mirrors the InitiateMultipartUploadResult document.
type MpuInitiateDoc struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// MpuAPIError builds the shape aws-sdk-go-v2 hands back for a backend answer.
func MpuAPIError(code, message string) error {
	return &smithy.GenericAPIError{Code: code, Message: message}
}

// MpuErrReader fails on the first read, standing in for a client that dies mid-body.
type MpuErrReader struct{}

func (MpuErrReader) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

// MpuFailingWriter accepts headers but refuses to write a body.
type MpuFailingWriter struct {
	headers http.Header
	status  int
}

func (w *MpuFailingWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = http.Header{}
	}
	return w.headers
}
func (w *MpuFailingWriter) Write([]byte) (int, error) { return 0, errors.New("client went away") }
func (w *MpuFailingWriter) WriteHeader(code int)      { w.status = code }

// MpuUnmarshalableDoc cannot be rendered by encoding/xml.
type MpuUnmarshalableDoc struct {
	XMLName xml.Name `xml:"Bad"`
	Ch      chan int `xml:"Ch"`
}

// MpuPayload builds a deterministic byte pattern of the requested size.
func MpuPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

func MpuDigest(b []byte) [32]byte { return sha256.Sum256(b) }

// MpuTLSState marks a request as having arrived over TLS.
var MpuTLSState = tls.ConnectionState{}

// ---------------------------------------------------------------------------
// CreateMultipartUpload
// ---------------------------------------------------------------------------

func TestMpuCreateReturnsUploadIDAndForwardsEntityHeaders(t *testing.T) {
	env := MpuNewEnv(t)

	var captured *s3.CreateMultipartUploadInput
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	req.Header.Set("Content-Type", "application/x-tar")
	// aws-chunked describes the request framing, not the stored object.
	req.Header.Set("Content-Encoding", "aws-chunked,gzip")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Content-Disposition", `attachment; filename="backup.tar"`)
	req.Header.Set("Content-Language", "en-GB")
	req.Header.Set("X-Amz-Meta-Owner", "velero")

	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	var doc MpuInitiateDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, MpuBucket, doc.Bucket)
	assert.Equal(t, MpuKey, doc.Key)
	assert.Equal(t, MpuUploadID, doc.UploadID, "the client can only continue with the upload id it is told")

	require.NotNil(t, captured)
	assert.Equal(t, MpuBucket, aws.ToString(captured.Bucket))
	assert.Equal(t, MpuKey, aws.ToString(captured.Key))
	assert.Equal(t, "application/x-tar", aws.ToString(captured.ContentType))
	assert.Equal(t, "gzip", aws.ToString(captured.ContentEncoding), "aws-chunked framing must not be recorded on the object")
	assert.Equal(t, "no-store", aws.ToString(captured.CacheControl))
	assert.Equal(t, `attachment; filename="backup.tar"`, aws.ToString(captured.ContentDisposition))
	assert.Equal(t, "en-GB", aws.ToString(captured.ContentLanguage))
	assert.Equal(t, "velero", captured.Metadata["owner"])

	env.backend.AssertExpectations(t)
}

func TestMpuCreateOmitsAbsentEntityHeaders(t *testing.T) {
	env := MpuNewEnv(t)

	var captured *s3.CreateMultipartUploadInput
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	// A bare aws-chunked value must leave nothing behind.
	req.Header.Set("Content-Encoding", "aws-chunked")

	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)
	assert.Nil(t, captured.ContentType)
	assert.Nil(t, captured.ContentEncoding, "aws-chunked alone must not become a stored Content-Encoding")
	assert.Nil(t, captured.CacheControl)
	assert.Nil(t, captured.ContentDisposition)
	assert.Nil(t, captured.ContentLanguage)
	assert.Nil(t, captured.Metadata, "no x-amz-meta-* header must not produce an empty metadata map")

	env.backend.AssertExpectations(t)
}

// TestMpuCreateSilentlyDropsRequestDirectives records the "silent 200" surface of
// CreateMultipartUpload: the headers below are accepted, never forwarded and never
// rejected, so a client is told its request succeeded as asked.
func TestMpuCreateSilentlyDropsRequestDirectives(t *testing.T) {
	env := MpuNewEnv(t)

	var captured *s3.CreateMultipartUploadInput
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	req.Header.Set("x-amz-storage-class", "GLACIER")
	req.Header.Set("x-amz-tagging", "team=platform")
	req.Header.Set("x-amz-acl", "public-read")
	req.Header.Set("x-amz-server-side-encryption", "aws:kms")
	req.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", "arn:aws:kms:eu-central-1:1:key/abc")
	req.Header.Set("x-amz-object-lock-mode", "COMPLIANCE")
	req.Header.Set("x-amz-website-redirect-location", "/elsewhere")
	req.Header.Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")

	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the request is accepted in full")
	require.NotNil(t, captured)
	assert.Empty(t, captured.StorageClass, "storage class is dropped, so GLACIER silently becomes STANDARD")
	assert.Nil(t, captured.Tagging)
	assert.Empty(t, captured.ACL)
	assert.Empty(t, captured.ServerSideEncryption)
	assert.Nil(t, captured.SSEKMSKeyId)
	assert.Empty(t, captured.ObjectLockMode)
	assert.Nil(t, captured.WebsiteRedirectLocation)
	assert.Nil(t, captured.Expires)

	env.backend.AssertExpectations(t)
}

func TestMpuCreateBackendErrorsMapToS3Codes(t *testing.T) {
	cases := []struct {
		name       string
		backendErr error
		wantStatus int
		wantCode   string
	}{
		{"no such bucket", MpuAPIError("NoSuchBucket", "The specified bucket does not exist"), http.StatusNotFound, "NoSuchBucket"},
		{"access denied", MpuAPIError("AccessDenied", ""), http.StatusForbidden, "AccessDenied"},
		{"network failure", errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"), http.StatusInternalServerError, "InternalError"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
				Return((*s3.CreateMultipartUploadOutput)(nil), tc.backendErr)

			req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
			w := httptest.NewRecorder()
			env.create().Handle(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, MpuBucket+"/"+MpuKey, doc.Resource)
			assert.NotContains(t, doc.Message, "10.0.0.1", "backend transport detail must not reach the client")

			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuCreateAbortsBackendUploadWhenEncryptionInitFails covers the compensating
// abort: without it the backend keeps an upload the client never learns about.
func TestMpuCreateAbortsBackendUploadWhenEncryptionInitFails(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	// The backend hands out the same upload id again, so the encryption session
	// already exists and initialisation fails.
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		UploadId: aws.String(MpuUploadID),
	}, nil).Once()

	var aborted *s3.AbortMultipartUploadInput
	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		aborted = args.Get(1).(*s3.AbortMultipartUploadInput)
	}).Return((*s3.AbortMultipartUploadOutput)(nil), errors.New("abort also failed"))

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
	require.NotNil(t, aborted, "the orphaned backend upload must be aborted")
	assert.Equal(t, MpuUploadID, aws.ToString(aborted.UploadId))

	env.backend.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// UploadPart
// ---------------------------------------------------------------------------

// TestMpuUploadPartNumberBounds pins what the handler does at the AWS part-number
// bounds. Bounds themselves are right (1..10000), but every rejection is served as
// text/plain, not as the S3 <Error> document AWS answers with, so an SDK client
// gets an unparseable body instead of an error code.
func TestMpuUploadPartNumberBounds(t *testing.T) {
	cases := []struct {
		name     string
		part     string
		wantBody string
	}{
		{"zero is below the range", "0", "Invalid partNumber"},
		{"one is the lower bound", "1", "Invalid upload ID"},
		{"ten thousand is the upper bound", "10000", "Invalid upload ID"},
		{"ten thousand and one is above the range", "10001", "Invalid partNumber"},
		{"negative", "-1", "Invalid partNumber"},
		{"not a number", "abc", "Invalid partNumber"},
		{"fractional", "1.5", "Invalid partNumber"},
		{"leading space", "%201", "Invalid partNumber"},
		{"int64 overflow", "99999999999999999999", "Invalid partNumber"},
		{"absent", "", "Missing uploadId or partNumber"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)

			url := fmt.Sprintf("/%s/%s?partNumber=%s&uploadId=no-such-upload", MpuBucket, MpuKey, tc.part)
			req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("payload"))))
			w := httptest.NewRecorder()
			env.upload().Handle(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), tc.wantBody)
			// Deviation from S3: AWS answers an <Error> document; this is http.Error.
			assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
		})
	}
}

// TestMpuUploadUnknownUploadIDIsNotNoSuchUpload records the status/code deviation:
// AWS answers 404 NoSuchUpload for an upload id it does not know.
func TestMpuUploadUnknownUploadIDIsNotNoSuchUpload(t *testing.T) {
	env := MpuNewEnv(t)

	url := fmt.Sprintf("/%s/%s?partNumber=1&uploadId=never-created", MpuBucket, MpuKey)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("x"))))
	w := httptest.NewRecorder()
	env.upload().Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "AWS documents 404 NoSuchUpload here")
	assert.Equal(t, "Invalid upload ID\n", w.Body.String())
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
}

func TestMpuUploadMissingUploadIDIsRejected(t *testing.T) {
	env := MpuNewEnv(t)

	url := fmt.Sprintf("/%s/%s?partNumber=1", MpuBucket, MpuKey)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("x"))))
	w := httptest.NewRecorder()
	env.upload().Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "Missing uploadId or partNumber\n", w.Body.String())
}

func TestMpuUploadUnreadableBodyIsRejected(t *testing.T) {
	env := MpuNewEnv(t)

	url := fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", MpuBucket, MpuKey, MpuUploadID)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, nil))
	req.Body = io.NopCloser(MpuErrReader{})
	req.ContentLength = 64

	w := httptest.NewRecorder()
	env.upload().Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to read request body")
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
}

// TestMpuUploadStoresCiphertextNotPlaintext is the encryption-at-rest contract:
// whatever path the bytes take, the body handed to the backend is not the body the
// client sent.
func TestMpuUploadStoresCiphertextNotPlaintext(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, 64 * 1024}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)

			plaintext := MpuPayload(size)

			var stored []byte
			env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				input := args.Get(1).(*s3.UploadPartInput)
				body, err := io.ReadAll(input.Body)
				require.NoError(t, err)
				stored = body
			}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

			w := env.MpuUploadPart(t, MpuUploadID, 1, plaintext)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, `"part-1"`, w.Header().Get("ETag"))
			// AES-CTR is length preserving, so a size change would mean framing was added.
			assert.Len(t, stored, size)
			if size > 0 {
				assert.NotEqual(t, MpuDigest(plaintext), MpuDigest(stored),
					"plaintext must never reach the backend")
			}
			env.backend.AssertExpectations(t)
		})
	}
}

func TestMpuUploadForwardsBackendEncryptionHeaders(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{
		ETag:                 aws.String(`"part-1"`),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String("arn:aws:kms:eu-central-1:1:key/abc"),
	}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, []byte("hello"))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "aws:kms", w.Header().Get("x-amz-server-side-encryption"))
	assert.Equal(t, "arn:aws:kms:eu-central-1:1:key/abc", w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"))
	env.backend.AssertExpectations(t)
}

func TestMpuUploadWithoutBackendETagStillSucceeds(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, []byte("hello"))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("ETag"))
	env.backend.AssertExpectations(t)
}

func TestMpuUploadBackendErrorsMapToS3Codes(t *testing.T) {
	cases := []struct {
		name       string
		backendErr error
		wantStatus int
		wantCode   string
	}{
		{"no such upload", MpuAPIError("NoSuchUpload", ""), http.StatusNotFound, "NoSuchUpload"},
		{"access denied", MpuAPIError("AccessDenied", ""), http.StatusForbidden, "AccessDenied"},
		{"entity too large", MpuAPIError("EntityTooLarge", "Your proposed upload exceeds the maximum allowed size"), http.StatusBadRequest, "EntityTooLarge"},
		{"slow down", MpuAPIError("SlowDown", ""), http.StatusServiceUnavailable, "SlowDown"},
		{"transport failure", errors.New("EOF from 10.0.0.1:9000"), http.StatusInternalServerError, "InternalError"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)

			env.backend.On("UploadPart", mock.Anything, mock.Anything).
				Return((*s3.UploadPartOutput)(nil), tc.backendErr)

			w := env.MpuUploadPart(t, MpuUploadID, 1, []byte("payload"))

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, MpuBucket+"/"+MpuKey, doc.Resource)
			assert.NotContains(t, doc.Message, "10.0.0.1")
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuUploadSilentlyDropsClientChecksumsAndSSEC records a "silent 200": the
// client asks for its own SSE-C key and for checksum verification, is answered 200,
// and neither reaches the backend. Content-MD5 is dropped deliberately (the body is
// ciphertext); the SSE-C headers are dropped without any decision being taken.
func TestMpuUploadSilentlyDropsClientChecksumsAndSSEC(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	var captured *s3.UploadPartInput
	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.UploadPartInput)
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

	url := fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", MpuBucket, MpuKey, MpuUploadID)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("payload"))))
	req.Header.Set("Content-MD5", "rL0Y20zC+Fzt72VPzMSk2A==")
	req.Header.Set("x-amz-checksum-sha256", "3q2+7w==")
	req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	req.Header.Set("x-amz-server-side-encryption-customer-key", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	req.Header.Set("x-amz-server-side-encryption-customer-key-MD5", "u7mBnA4KHdb3wXPBEbxzRA==")

	w := httptest.NewRecorder()
	env.upload().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the request is accepted in full")
	require.NotNil(t, captured)
	assert.Nil(t, captured.ContentMD5, "a plaintext digest must not travel with a ciphertext body")
	assert.Nil(t, captured.ChecksumSHA256)
	assert.Nil(t, captured.SSECustomerKey, "the client's own encryption key is ignored, not refused")
	assert.Empty(t, captured.SSECustomerAlgorithm)
	env.backend.AssertExpectations(t)
}

// TestMpuUploadBuffersWholePartBeforeCallingBackend pins the behaviour ticket 012
// describes: the part is fully materialised as ciphertext in memory and handed to
// the backend as a seekable byte slice with an exact ContentLength, so nothing on
// this path streams. Update this test together with that rework.
func TestMpuUploadBuffersWholePartBeforeCallingBackend(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	const partSize = 512 * 1024
	var bodyIsSeekableBuffer bool
	var declaredLength int64
	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		_, bodyIsSeekableBuffer = input.Body.(*bytes.Reader)
		declaredLength = aws.ToInt64(input.ContentLength)
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(partSize))

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, bodyIsSeekableBuffer, "the whole ciphertext part is resident in memory before the backend call")
	assert.Equal(t, int64(partSize), declaredLength)
	env.backend.AssertExpectations(t)
}

// TestMpuUploadOutOfOrderPartParksTheRequestGoroutine shows that a part which
// arrives ahead of its turn parks the request goroutine with no timeout and no
// reaction to the client having disconnected: the only thing that can release it is
// the missing part arriving, or this test handing it an error directly.
func TestMpuUploadOutOfOrderPartParksTheRequestGoroutine(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	url := fmt.Sprintf("/%s/%s?partNumber=2&uploadId=%s", MpuBucket, MpuKey, MpuUploadID)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader(MpuPayload(32))))
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // the client is already gone
	req = req.WithContext(ctx)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		env.upload().Handle(rec, req)
		done <- rec.Code
	}()

	state, err := env.enc.GetMultipartUploadState(MpuUploadID)
	require.NoError(t, err)

	// Wait until the part is parked, then confirm it stays parked: neither the
	// cancelled request context nor any deadline gets it out.
	parked := MpuWaitForPendingPart(t, state, 2)
	select {
	case code := <-done:
		t.Fatalf("part 2 returned %d without part 1 ever arriving", code)
	case <-time.After(200 * time.Millisecond):
	}
	assert.Error(t, ctx.Err(), "the client disconnected and the goroutine still waits")

	// Release it by hand; nothing in the request path would ever do this.
	parked.ErrorChan <- errors.New("released by the test")

	select {
	case code := <-done:
		assert.Equal(t, http.StatusInternalServerError, code)
	case <-time.After(10 * time.Second):
		t.Fatal("the parked part never returned")
	}
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
}

// MpuWaitForPendingPart returns the buffer a part is parked in once it appears.
func MpuWaitForPendingPart(t *testing.T, state *orchestration.MultipartSession, partNumber int) *orchestration.PartBuffer {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state.OrderingMutex.Lock()
		buf, ok := state.PendingParts[partNumber]
		state.OrderingMutex.Unlock()
		if ok {
			return buf
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("part %d was never buffered", partNumber)
	return nil
}

// TestMpuUploadUnexpectedSessionShapeReturns500 reaches the defensive branch that
// fires when a session is neither multipart nor AES-CTR.
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestMpuUploadUnexpectedSessionShapeReturns500(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	state, err := env.enc.GetMultipartUploadState(MpuUploadID)
	require.NoError(t, err)
	state.ContentType = "whole"
	delete(state.Metadata, "s3ep-dek-algorithm")

	w := env.MpuUploadPart(t, MpuUploadID, 1, []byte("payload"))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	doc := MpuParseError(t, w.Body.Bytes())
	assert.Equal(t, "InternalError", doc.Code)
	assert.Contains(t, doc.Message, "unexpected handler selection")
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// CompleteMultipartUpload
// ---------------------------------------------------------------------------

// TestMpuCompleteRejectsMalformedRequests records the S3 error code the handler
// answers with for every malformed CompleteMultipartUpload. Every one of these is a
// client mistake that AWS answers 400 for; the proxy answers 500 InternalError,
// which tells an SDK to retry a request that can never succeed.
func TestMpuCompleteRejectsMalformedRequests(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		body     string
		awsCode  string
		awsState int
	}{
		{"missing uploadId", "", MpuCompleteBody(1), "InvalidRequest", http.StatusBadRequest},
		{"malformed xml", "?uploadId=" + MpuUploadID, "<CompleteMultipartUpload><Part>", "MalformedXML", http.StatusBadRequest},
		{"not xml at all", "?uploadId=" + MpuUploadID, "{\"parts\":[]}", "MalformedXML", http.StatusBadRequest},
		{"empty part list", "?uploadId=" + MpuUploadID, "<CompleteMultipartUpload></CompleteMultipartUpload>", "MalformedXML", http.StatusBadRequest},
		{"part number zero", "?uploadId=" + MpuUploadID, MpuCompleteBody(0), "InvalidPart", http.StatusBadRequest},
		{"part number above 10000", "?uploadId=" + MpuUploadID, MpuCompleteBody(10001), "InvalidPart", http.StatusBadRequest},
		{"duplicate part numbers", "?uploadId=" + MpuUploadID, MpuCompleteBody(1, 1), "InvalidPartOrder", http.StatusBadRequest},
		{"missing etag", "?uploadId=" + MpuUploadID,
			"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag></ETag></Part></CompleteMultipartUpload>",
			"InvalidPart", http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)

			req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+tc.query, strings.NewReader(tc.body)))
			w := httptest.NewRecorder()
			env.complete().Handle(w, req)

			doc := MpuParseError(t, w.Body.Bytes())
			// Current behaviour, deliberately pinned so the deviation is visible:
			// a client error is reported as a server error.
			assert.Equal(t, http.StatusInternalServerError, w.Code,
				"AWS answers %d %s here", tc.awsState, tc.awsCode)
			assert.Equal(t, "InternalError", doc.Code, "AWS answers %s here", tc.awsCode)
			assert.Equal(t, "We encountered an internal error. Please try again.", doc.Message)

			env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
			env.backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
		})
	}
}

func TestMpuCompleteUnreadableBodyIsRejected(t *testing.T) {
	env := MpuNewEnv(t)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil))
	req.Body = io.NopCloser(MpuErrReader{})

	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// TestMpuCompleteUnknownUploadIDIsNotNoSuchUpload: AWS answers 404 NoSuchUpload for
// an upload id it does not know.
func TestMpuCompleteUnknownUploadIDIsNotNoSuchUpload(t *testing.T) {
	env := MpuNewEnv(t)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId=never-created",
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "AWS answers 404 NoSuchUpload here")
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// TestMpuCompleteAcceptsPartsOutOfOrder: AWS requires ascending part numbers and
// answers 400 InvalidPartOrder otherwise. This handler sorts the list instead and
// reports success, so a client whose ordering is broken is never told.
func TestMpuCompleteAcceptsPartsOutOfOrder(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	var forwarded []int32
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.CompleteMultipartUploadInput)
		for _, p := range input.MultipartUpload.Parts {
			forwarded = append(forwarded, aws.ToInt32(p.PartNumber))
		}
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{}, nil)
	env.backend.On("CopyObject", mock.Anything, mock.Anything).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
	}, nil)

	body := "<CompleteMultipartUpload>" +
		"<Part><PartNumber>3</PartNumber><ETag>\"e3\"</ETag></Part>" +
		"<Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag></Part>" +
		"<Part><PartNumber>2</PartNumber><ETag>\"e2\"</ETag></Part>" +
		"</CompleteMultipartUpload>"

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, strings.NewReader(body)))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "AWS answers 400 InvalidPartOrder here")
	assert.Equal(t, []int32{1, 2, 3}, forwarded, "the handler silently reorders the client's list")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteStripsETagQuotesForTheBackend keeps the shape of the completion
// document the backend receives under test.
func TestMpuCompleteStripsETagQuotesForTheBackend(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	var forwarded []string
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.CompleteMultipartUploadInput)
		for _, p := range input.MultipartUpload.Parts {
			forwarded = append(forwarded, aws.ToString(p.ETag))
		}
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{}, nil)
	env.backend.On("CopyObject", mock.Anything, mock.Anything).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
	}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1, 2))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"etag-1", "etag-2"}, forwarded)
	env.backend.AssertExpectations(t)
}

func TestMpuCompleteBackendErrorsMapToS3Codes(t *testing.T) {
	cases := []struct {
		name       string
		backendErr error
		wantStatus int
		wantCode   string
	}{
		{"a listed part was never uploaded", MpuAPIError("InvalidPart", ""), http.StatusBadRequest, "InvalidPart"},
		{"the parts are not in order at the backend", MpuAPIError("InvalidPartOrder", "The list of parts was not in ascending order"), http.StatusBadRequest, "InvalidPartOrder"},
		{"the upload is gone", MpuAPIError("NoSuchUpload", ""), http.StatusNotFound, "NoSuchUpload"},
		{"a part is below the minimum size", MpuAPIError("EntityTooSmall", "Your proposed upload is smaller than the minimum allowed size"), http.StatusBadRequest, "EntityTooSmall"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)

			env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
				Return((*s3.CompleteMultipartUploadOutput)(nil), tc.backendErr)

			req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
				strings.NewReader(MpuCompleteBody(1))))
			w := httptest.NewRecorder()
			env.complete().Handle(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			env.backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuCompleteLocationPointsAtTheProxy: the backend endpoint is internal and
// must never appear in the response the client parses.
func TestMpuCompleteLocationPointsAtTheProxy(t *testing.T) {
	for _, tls := range []bool{false, true} {
		name := "http"
		if tls {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)

			env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
				Return(&s3.CompleteMultipartUploadOutput{
					ETag:     aws.String(`"mpu-etag"`),
					Location: aws.String("https://minio.internal:9000/cov-bucket/cov/key.bin"),
				}, nil)
			env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{}, nil)
			env.backend.On("CopyObject", mock.Anything, mock.Anything).Return(&s3.CopyObjectOutput{
				CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
			}, nil)

			req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
				strings.NewReader(MpuCompleteBody(1))))
			req.Host = "proxy.example.com:8080"
			if tls {
				req.TLS = &MpuTLSState
			}

			w := httptest.NewRecorder()
			env.complete().Handle(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var doc MpuCompleteDoc
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
			assert.Equal(t, name+"://proxy.example.com:8080/"+MpuBucket+"/"+MpuKey, doc.Location)
			assert.NotContains(t, w.Body.String(), "minio.internal")
			assert.Equal(t, MpuBucket, doc.Bucket)
			assert.Equal(t, MpuKey, doc.Key)
			assert.Equal(t, `"copy-etag"`, doc.ETag)
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuCompleteSelfCopyFailureIsReportedAsFailure: the object is already stored
// at this point, so a client told "success" would own an object nothing can decrypt.
func TestMpuCompleteSelfCopyFailureIsReportedAsFailure(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{}, nil)
	// Real S3 refuses a CopyObject over 5 GiB, which is exactly this answer.
	env.backend.On("CopyObject", mock.Anything, mock.Anything).
		Return((*s3.CopyObjectOutput)(nil), MpuAPIError("InvalidRequest", "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120"))

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "InvalidRequest", MpuParseError(t, w.Body.Bytes()).Code)
	assert.NotContains(t, w.Body.String(), "CompleteMultipartUploadResult")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteSelfCopyRunsWhenHeadObjectFails covers the fallback in
// restateStoredAttributes: losing the entity headers is better than losing the
// encryption metadata.
func TestMpuCompleteSelfCopyRunsWhenHeadObjectFails(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).
		Return((*s3.HeadObjectOutput)(nil), MpuAPIError("AccessDenied", ""))

	var copied *s3.CopyObjectInput
	env.backend.On("CopyObject", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		copied = args.Get(1).(*s3.CopyObjectInput)
	}).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
	}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, copied, "the encryption metadata must still be written")
	assert.Equal(t, types.MetadataDirectiveReplace, copied.MetadataDirective)
	assert.Equal(t, MpuBucket+"/"+MpuKey, aws.ToString(copied.CopySource))
	assert.NotEmpty(t, copied.Metadata["s3ep-encrypted-dek"])
	assert.Nil(t, copied.ContentType, "nothing was read back, so nothing is restated")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteEncryptionMetadataWinsMergeCollision: the stored bytes are what the
// s3ep-* entries describe, whatever the client called its own metadata.
func TestMpuCompleteEncryptionMetadataWinsMergeCollision(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		Metadata: map[string]string{
			"owner":              "velero",
			"s3ep-dek-algorithm": "attacker-supplied",
		},
	}, nil)

	var copied *s3.CopyObjectInput
	env.backend.On("CopyObject", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		copied = args.Get(1).(*s3.CopyObjectInput)
	}).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
	}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, copied)
	assert.Equal(t, "velero", copied.Metadata["owner"], "user metadata survives")
	assert.Equal(t, "aes-ctr", copied.Metadata["s3ep-dek-algorithm"], "encryption metadata wins the collision")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteWithoutMetadataSkipsSelfCopy is the pass-through provider: no
// encryption metadata means nothing to attach and the multipart ETag stands.
func TestMpuCompleteWithoutMetadataSkipsSelfCopy(t *testing.T) {
	env := MpuNewNoneEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{
			ETag:                 aws.String(`"mpu-etag"`),
			VersionId:            aws.String("mpu-version"),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
			SSEKMSKeyId:          aws.String("kms-key"),
		}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"mpu-etag"`, w.Header().Get("ETag"))
	assert.Equal(t, "mpu-version", w.Header().Get("x-amz-version-id"))
	assert.Equal(t, "AES256", w.Header().Get("x-amz-server-side-encryption"))
	assert.Equal(t, "kms-key", w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"))
	env.backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
	env.backend.AssertNotCalled(t, "HeadObject", mock.Anything, mock.Anything)
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteAcceptsFewerPartsThanWereUploaded: S3 lets a client complete with a
// subset of the parts it uploaded and discards the rest. The proxy's integrity tag
// was accumulated over every part it encrypted, so the object it stores here can
// never satisfy that tag again.
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestMpuCompleteAcceptsFewerPartsThanWereUploaded(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(64)).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(64)).Code)

	var forwarded int
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		forwarded = len(args.Get(1).(*s3.CompleteMultipartUploadInput).MultipartUpload.Parts)
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	env.backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{}, nil)

	var copied *s3.CopyObjectInput
	env.backend.On("CopyObject", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		copied = args.Get(1).(*s3.CopyObjectInput)
	}).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{ETag: aws.String(`"copy-etag"`)},
	}, nil)

	// Only part 1 is listed; part 2 is discarded by the backend.
	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
		strings.NewReader(MpuCompleteBody(1))))
	w := httptest.NewRecorder()
	env.complete().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the client is told the upload succeeded")
	assert.Equal(t, 1, forwarded)
	require.NotNil(t, copied)
	assert.NotEmpty(t, copied.Metadata["s3ep-hmac"],
		"the stored integrity tag covers both parts while the object holds one")
	env.backend.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// AbortMultipartUpload
// ---------------------------------------------------------------------------

func TestMpuAbortKnownUploadReturns204AndClearsSession(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	var aborted *s3.AbortMultipartUploadInput
	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		aborted = args.Get(1).(*s3.AbortMultipartUploadInput)
	}).Return(&s3.AbortMultipartUploadOutput{}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil))
	w := httptest.NewRecorder()
	env.abort().Handle(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String(), "204 must carry no body")
	require.NotNil(t, aborted)
	assert.Equal(t, MpuBucket, aws.ToString(aborted.Bucket))
	assert.Equal(t, MpuKey, aws.ToString(aborted.Key))
	assert.Equal(t, MpuUploadID, aws.ToString(aborted.UploadId))

	// The encryption session is gone: a part uploaded afterwards is refused.
	_, err := env.enc.GetMultipartUploadState(MpuUploadID)
	assert.Error(t, err, "the encryption session must not outlive the abort")

	env.backend.AssertExpectations(t)
}

// TestMpuAbortWithoutEncryptionSessionStillSucceeds: the client asked for the
// backend upload to go away, and a missing local session must not stop that.
func TestMpuAbortWithoutEncryptionSessionStillSucceeds(t *testing.T) {
	env := MpuNewEnv(t)

	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.AbortMultipartUploadOutput{}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey+"?uploadId=never-created", nil))
	w := httptest.NewRecorder()
	env.abort().Handle(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	env.backend.AssertExpectations(t)
}

func TestMpuAbortBackendErrorsMapToS3Codes(t *testing.T) {
	cases := []struct {
		name       string
		backendErr error
		wantStatus int
		wantCode   string
	}{
		{"unknown upload", MpuAPIError("NoSuchUpload", ""), http.StatusNotFound, "NoSuchUpload"},
		{"unknown bucket", MpuAPIError("NoSuchBucket", ""), http.StatusNotFound, "NoSuchBucket"},
		{"denied", MpuAPIError("AccessDenied", ""), http.StatusForbidden, "AccessDenied"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
				Return((*s3.AbortMultipartUploadOutput)(nil), tc.backendErr)

			req := MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil))
			w := httptest.NewRecorder()
			env.abort().Handle(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, MpuBucket+"/"+MpuKey, doc.Resource)
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuAbortMissingUploadIDIsReportedAsServerError: AWS answers 400 for a request
// without an upload id.
func TestMpuAbortMissingUploadIDIsReportedAsServerError(t *testing.T) {
	env := MpuNewEnv(t)

	req := MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey, nil))
	w := httptest.NewRecorder()
	env.abort().Handle(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "AWS answers 400 InvalidRequest here")
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// ListParts / ListMultipartUploads
// ---------------------------------------------------------------------------

// TestMpuListPartsNeverReportsAnyPart is the largest silent 200 on this surface:
// the handler answers a canned, empty ListPartsResult without ever asking the
// backend, so a client that lists parts to resume or to verify an upload is told
// the upload has none.
func TestMpuListPartsNeverReportsAnyPart(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p1"`)}, nil)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(32)).Code)

	url := fmt.Sprintf("/%s/%s?uploadId=%s&max-parts=2&part-number-marker=7&encoding-type=url", MpuBucket, MpuKey, MpuUploadID)
	req := MpuVars(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	env.list().HandleListParts(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	var doc MpuListPartsDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, MpuBucket, doc.Bucket)
	assert.Equal(t, MpuKey, doc.Key)
	assert.Equal(t, MpuUploadID, doc.UploadID)
	assert.Equal(t, "STANDARD", doc.StorageClass)
	assert.Empty(t, doc.Parts, "a part was uploaded and is not listed")
	// Pagination is parsed by nobody: the canned answer ignores both parameters.
	assert.Equal(t, 1000, doc.MaxParts, "the client asked for max-parts=2")
	assert.Equal(t, 0, doc.PartNumberMarker, "the client asked for part-number-marker=7")
	assert.Equal(t, 0, doc.NextPartNumberMarker)
	assert.False(t, doc.IsTruncated)

	env.backend.AssertNotCalled(t, "ListParts", mock.Anything, mock.Anything)
}

func TestMpuListPartsMissingUploadIDIsReportedAsServerError(t *testing.T) {
	env := MpuNewEnv(t)

	req := MpuVars(httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"/"+MpuKey, nil))
	w := httptest.NewRecorder()
	env.list().HandleListParts(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "AWS answers 400 InvalidRequest here")
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
}

func TestMpuListMultipartUploadsIsNotImplemented(t *testing.T) {
	env := MpuNewEnv(t)

	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"?uploads", nil),
		map[string]string{"bucket": MpuBucket})
	w := httptest.NewRecorder()
	env.list().HandleListMultipartUploads(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	doc := MpuParseError(t, w.Body.Bytes())
	assert.Equal(t, "NotImplemented", doc.Code)
	assert.Equal(t, "ListMultipartUploads", doc.Resource)
	env.backend.AssertNotCalled(t, "ListMultipartUploads", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// UploadPartCopy
// ---------------------------------------------------------------------------

// TestMpuUploadPartCopyRefusesEveryVariant: the operation is refused whether or not
// the client asks for a byte range, and nothing reaches the backend.
func TestMpuUploadPartCopyRefusesEveryVariant(t *testing.T) {
	cases := []struct {
		name        string
		copySource  string
		sourceRange string
	}{
		{"whole source object", "/src-bucket/src-key", ""},
		{"with a byte range", "/src-bucket/src-key", "bytes=0-5242879"},
		{"with a version id", "/src-bucket/src-key?versionId=abc", "bytes=5242880-10485759"},
		{"with an absurd range", "/src-bucket/src-key", "bytes=99999999999999-0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			handler := NewCopyHandler(env.backend, env.enc, env.logger)

			url := fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", MpuBucket, MpuKey, MpuUploadID)
			req := MpuVars(httptest.NewRequest(http.MethodPut, url, nil))
			req.Header.Set("x-amz-copy-source", tc.copySource)
			if tc.sourceRange != "" {
				req.Header.Set("x-amz-copy-source-range", tc.sourceRange)
			}

			w := httptest.NewRecorder()
			handler.Handle(w, req)

			assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, "NotSupportedWithEncryption", doc.Code)
			assert.Equal(t, "UploadPartCopy", doc.Resource)
			env.backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
			env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
		})
	}
}

// ---------------------------------------------------------------------------
// XML rendering
// ---------------------------------------------------------------------------

func TestMpuWriteXMLDocumentEmitsDeclarationAndEscapes(t *testing.T) {
	env := MpuNewEnv(t)

	w := httptest.NewRecorder()
	writeXMLDocument(w, env.logger, initiateMultipartUploadResult{
		Bucket:   `b&<"`,
		Key:      `k</Key><Injected/>`,
		UploadID: "id",
	})

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.True(t, strings.HasPrefix(w.Body.String(), xml.Header))
	assert.NotContains(t, w.Body.String(), "<Injected/>")

	var doc MpuInitiateDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, `b&<"`, doc.Bucket)
	assert.Equal(t, `k</Key><Injected/>`, doc.Key)
}

func TestMpuWriteXMLDocumentMarshalFailureAnswers500WithoutBody(t *testing.T) {
	env := MpuNewEnv(t)

	w := httptest.NewRecorder()
	writeXMLDocument(w, env.logger, MpuUnmarshalableDoc{})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Body.String(), "a failed render must not leave a half document behind")
	assert.Empty(t, w.Header().Get("Content-Type"), "the XML content type must not be promised")
}

func TestMpuWriteXMLDocumentSurvivesAFailingWriter(t *testing.T) {
	env := MpuNewEnv(t)

	w := &MpuFailingWriter{}
	assert.NotPanics(t, func() {
		writeXMLDocument(w, env.logger, listPartsResult{Bucket: MpuBucket, Key: MpuKey, MaxParts: 1000})
	})
	assert.Equal(t, http.StatusOK, w.status)
}

func TestMpuCompleteResultDocumentRoundTrips(t *testing.T) {
	env := MpuNewEnv(t)

	w := httptest.NewRecorder()
	writeXMLDocument(w, env.logger, completeMultipartUploadResult{
		Location: "http://proxy/b/k",
		Bucket:   "b",
		Key:      "k",
		ETag:     `"e"`,
	})

	require.Equal(t, http.StatusOK, w.Code)
	var doc MpuCompleteDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "http://proxy/b/k", doc.Location)
	assert.Equal(t, `"e"`, doc.ETag)
}

// ---------------------------------------------------------------------------
// Handler facade
// ---------------------------------------------------------------------------

func TestMpuHandlerFacadeWiresEverySubHandler(t *testing.T) {
	env := MpuNewEnv(t)
	h := NewHandler(env.backend, env.enc, env.logger, "s3ep-", env.cfg)

	require.NotNil(t, h.GetCreateHandler())
	require.NotNil(t, h.GetUploadHandler())
	require.NotNil(t, h.GetCopyHandler())
	require.NotNil(t, h.GetCompleteHandler())
	require.NotNil(t, h.GetAbortHandler())
	require.NotNil(t, h.GetListHandler())
	assert.Same(t, h.GetCreateHandler(), h.GetCreateHandler(), "the facade must hand out one instance, not a new one per call")

	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil).Once()
	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.AbortMultipartUploadOutput{}, nil).Once()

	createW := httptest.NewRecorder()
	h.HandleCreate(createW, MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil)))
	require.Equal(t, http.StatusOK, createW.Code)

	uploadW := httptest.NewRecorder()
	h.HandleUploadPart(uploadW, MpuVars(httptest.NewRequest(http.MethodPut, "/"+MpuBucket+"/"+MpuKey, nil)))
	assert.Equal(t, http.StatusBadRequest, uploadW.Code)

	completeW := httptest.NewRecorder()
	h.HandleComplete(completeW, MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey, nil)))
	assert.Equal(t, http.StatusInternalServerError, completeW.Code)

	abortW := httptest.NewRecorder()
	h.HandleAbort(abortW, MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil)))
	assert.Equal(t, http.StatusNoContent, abortW.Code)

	listPartsW := httptest.NewRecorder()
	h.HandleListParts(listPartsW, MpuVars(httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil)))
	assert.Equal(t, http.StatusOK, listPartsW.Code)
	assert.Contains(t, listPartsW.Body.String(), "ListPartsResult")

	listUploadsW := httptest.NewRecorder()
	h.HandleListMultipartUploads(listUploadsW, mux.SetURLVars(
		httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"?uploads", nil),
		map[string]string{"bucket": MpuBucket}))
	assert.Equal(t, http.StatusNotImplemented, listUploadsW.Code)

	env.backend.AssertExpectations(t)
}

// TestMpuUploadEncryptionFailureNeverReachesTheBackend: when the part cannot be
// encrypted the request must fail, and no bytes may be stored.
func TestMpuUploadEncryptionFailureNeverReachesTheBackend(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	state, err := env.enc.GetMultipartUploadState(MpuUploadID)
	require.NoError(t, err)
	state.CTREncryptor = nil // the session lost its stream cipher

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(128))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "InternalError", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
}

// TestMpuUploadSurvivesSessionVanishingMidFlight: a concurrent abort removes the
// session while the part is at the backend. The part is stored, so the client is
// told so; only the local bookkeeping is lost.
func TestMpuUploadSurvivesSessionVanishingMidFlight(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		require.NoError(t, env.enc.CleanupMultipartUpload(MpuUploadID))
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(64))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"part-1"`, w.Header().Get("ETag"))
	env.backend.AssertExpectations(t)
}

// TestMpuUploadRetryOfAnAlreadyProcessedPartNeverReturns is the same parking
// mechanism reached by an ordinary client: S3 lets a client re-upload a part, and
// every AWS SDK retries a part whose response it did not like. The second attempt
// carries a part number the session has already moved past, so it parks with
// nothing left that could ever release it.
func TestMpuUploadRetryOfAnAlreadyProcessedPartNeverReturns(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)

	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(48)).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(48)).Code)

	done := make(chan int, 1)
	go func() {
		done <- env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(48)).Code
	}()

	state, err := env.enc.GetMultipartUploadState(MpuUploadID)
	require.NoError(t, err)
	parked := MpuWaitForPendingPart(t, state, 2)

	select {
	case code := <-done:
		t.Fatalf("the retried part returned %d; the deadlock this pins is gone", code)
	case <-time.After(200 * time.Millisecond):
	}

	parked.ErrorChan <- errors.New("released by the test")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retried part never returned")
	}
}
