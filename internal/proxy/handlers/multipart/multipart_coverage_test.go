package multipart

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

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
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
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
	// MpuSegment is the plaintext one stored segment carries. A client part that is
	// not a whole number of segments cannot be stored where it lies, which is the
	// single fact that shapes every upload case below.
	MpuSegment = dataencryption.SegmentSize

	// MpuStorablePart is a part the backend takes in the middle of an upload:
	// whole segments and at or above the S3 minimum. Anything smaller can only
	// be an object's last part, so the proxy holds it until Complete.
	MpuStorablePart = 80 * MpuSegment
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

	// etags is what the handler answered for each part, which is what a client
	// puts into its completion list. Complete checks that list against the
	// proxy's own part table (ADR 0011 D6), so a fabricated tag is refused.
	etags map[int]string
}

// MpuNewEnv builds an environment whose active provider encrypts, which is the
// configuration a production deployment runs.
func MpuNewEnv(t *testing.T) *MpuEnv {
	t.Helper()
	return MpuNewEnvWithProvider(t, config.EncryptionProvider{
		Alias:  "cov-aes",
		Type:   "aes",
		Config: map[string]interface{}{"aes_key": MpuAESKey},
	})
}

// MpuNewExitEnv builds an environment on the exit provider, the one an operator
// selects to leave the product.
func MpuNewExitEnv(t *testing.T) *MpuEnv {
	t.Helper()
	return MpuNewEnvWithProvider(t, config.EncryptionProvider{
		Alias: "cov-exit",
		Type:  "exit",
	})
}

func MpuNewEnvWithProvider(t *testing.T, provider config.EncryptionProvider) *MpuEnv {
	t.Helper()

	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: provider.Alias,
			MetadataKeyPrefix:     &prefix,
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
// exists for uploadID, exactly as a client would establish it. It returns the
// object metadata the proxy attached there, which is what makes the stored chain
// readable afterwards.
func (e *MpuEnv) MpuInitiate(t *testing.T, uploadID string) map[string]string {
	t.Helper()
	var metadata map[string]string
	e.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		metadata = args.Get(1).(*s3.CreateMultipartUploadInput).Metadata
	}).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String(MpuBucket),
		Key:      aws.String(MpuKey),
		UploadId: aws.String(uploadID),
	}, nil).Once()

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	w := httptest.NewRecorder()
	e.create().Handle(w, req)
	require.Equal(t, http.StatusOK, w.Code, "test fixture: CreateMultipartUpload must succeed")
	return metadata
}

// MpuUploadPart drives one real part upload through the handler and keeps the
// ETag it answered with.
func (e *MpuEnv) MpuUploadPart(t *testing.T, uploadID string, partNumber int, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", MpuBucket, MpuKey, partNumber, uploadID)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body)))
	w := httptest.NewRecorder()
	e.upload().Handle(w, req)
	if etag := w.Header().Get("ETag"); etag != "" {
		if e.etags == nil {
			e.etags = make(map[int]string)
		}
		e.etags[partNumber] = strings.Trim(etag, "\"")
	}
	return w
}

// MpuComplete drives a CompleteMultipartUpload for the given client part list,
// in the order given, with the ETags the parts were answered with.
func (e *MpuEnv) MpuComplete(t *testing.T, uploadID string, parts ...int) *httptest.ResponseRecorder {
	t.Helper()
	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+uploadID,
		strings.NewReader(e.MpuCompleteBody(parts...))))
	w := httptest.NewRecorder()
	e.complete().Handle(w, req)
	return w
}

// MpuCompleteBody renders the completion document a client would send for these
// parts, in the order given.
func (e *MpuEnv) MpuCompleteBody(parts ...int) string {
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for _, number := range parts {
		etag, ok := e.etags[number]
		if !ok {
			etag = fmt.Sprintf("etag-%d", number)
		}
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%q</ETag></Part>", number, etag)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

// MpuCaptureParts accepts every part at the backend and keeps its stored bytes,
// keyed by part number. Reading the body here is what a backend does, so it also
// proves the declared length is the length the body delivers.
func (e *MpuEnv) MpuCaptureParts(t *testing.T) map[int][]byte {
	t.Helper()
	stored := make(map[int][]byte)
	e.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		body, err := io.ReadAll(input.Body)
		require.NoError(t, err)
		require.Equal(t, aws.ToInt64(input.ContentLength), int64(len(body)),
			"the declared part length must be the length the backend can read")
		stored[int(aws.ToInt32(input.PartNumber))] = body
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"stored"`)}, nil)
	return stored
}

// MpuChain concatenates the stored parts in part order, which is the object the
// backend holds once CompleteMultipartUpload returns.
func MpuChain(stored map[int][]byte) []byte {
	numbers := make([]int, 0, len(stored))
	for number := range stored {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)

	var chain []byte
	for _, number := range numbers {
		chain = append(chain, stored[number]...)
	}
	return chain
}

// MpuOpen decrypts a stored object through the manager. Nothing else can tell
// whether the parts the backend received really form one readable chain.
func (e *MpuEnv) MpuOpen(t *testing.T, metadata map[string]string, stored []byte) []byte {
	t.Helper()
	reader, err := e.enc.OpenSegmented(MpuKey, metadata, bytes.NewReader(stored))
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	plaintext, err := io.ReadAll(reader)
	require.NoError(t, err)
	return plaintext
}

// MpuStoredPart is the backend length a part of this plaintext length occupies:
// one nonce and one tag per segment. The trailer is not part of it — it closes
// the object once, at Complete.
func MpuStoredPart(plaintextLen int) int64 {
	return orchestration.PartStoredLen(int64(plaintextLen))
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
	// The object's own metadata always travels here; without a client entry it is
	// exactly the four keys and nothing else.
	assert.Len(t, captured.Metadata, 4)

	env.backend.AssertExpectations(t)
}

// TestMpuCreateSealsTheObjectBeforeTheUploadExists is the format change on this
// surface: the data key, the wrapped key and the whole metadata set are fixed
// before the backend is asked to open the upload, so nothing has to be attached
// afterwards and no rewrite follows completion.
func TestMpuCreateSealsTheObjectBeforeTheUploadExists(t *testing.T) {
	env := MpuNewEnv(t)

	var captured *s3.CreateMultipartUploadInput
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	req.Header.Set("X-Amz-Meta-Owner", "velero")
	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)
	assert.NotEmpty(t, captured.Metadata["s3ep-encrypted-dek"])
	assert.Equal(t, dataencryption.FormatID, captured.Metadata["s3ep-dek-algorithm"])
	assert.NotEmpty(t, captured.Metadata["s3ep-kek-fingerprint"])
	assert.NotEmpty(t, captured.Metadata["s3ep-kek-algorithm"])
	assert.Equal(t, "velero", captured.Metadata["owner"], "user metadata travels with it")
	// Neither key exists any more: every segment carries its own nonce, and
	// integrity is not separable from decryption.
	assert.NotContains(t, captured.Metadata, "s3ep-aes-iv")
	assert.NotContains(t, captured.Metadata, "s3ep-hmac")

	_, live := env.enc.SegmentedSession(MpuUploadID)
	assert.True(t, live, "the session must be reachable under the upload id the client was given")

	env.backend.AssertExpectations(t)
}

// TestMpuCreateDropsClientSuppliedEncryptionMetadata: the stored bytes are what
// the s3ep-* entries describe, so a client must not be able to name them itself.
func TestMpuCreateDropsClientSuppliedEncryptionMetadata(t *testing.T) {
	env := MpuNewEnv(t)

	var captured *s3.CreateMultipartUploadInput
	env.backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(1).(*s3.CreateMultipartUploadInput)
	}).Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String(MpuUploadID)}, nil)

	req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil))
	req.Header.Set("X-Amz-Meta-Owner", "velero")
	req.Header.Set("X-Amz-Meta-S3ep-Dek-Algorithm", "attacker-supplied")
	req.Header.Set("X-Amz-Meta-S3ep-Encrypted-Dek", "attacker-supplied")

	w := httptest.NewRecorder()
	env.create().Handle(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "velero", captured.Metadata["owner"], "user metadata survives")
	assert.Equal(t, dataencryption.FormatID, captured.Metadata["s3ep-dek-algorithm"])
	assert.NotEqual(t, "attacker-supplied", captured.Metadata["s3ep-encrypted-dek"])

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

// ---------------------------------------------------------------------------
// UploadPart
// ---------------------------------------------------------------------------

// TestMpuUploadPartNumberBounds pins what the handler does at the AWS part-number
// bounds (1..10000). A rejected part number is still served as text/plain rather
// than as the S3 <Error> document AWS answers with, so an SDK client gets an
// unparseable body; a part number inside the range reaches the session lookup and
// is answered properly.
func TestMpuUploadPartNumberBounds(t *testing.T) {
	cases := []struct {
		name string
		part string
		// wantBody is the plain-text rejection, empty when the part number is
		// accepted and the request reaches the session lookup.
		wantBody string
	}{
		{"zero is below the range", "0", "Invalid partNumber"},
		{"one is the lower bound", "1", ""},
		{"ten thousand is the upper bound", "10000", ""},
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

			if tc.wantBody == "" {
				assert.Equal(t, http.StatusNotFound, w.Code)
				assert.Equal(t, "NoSuchUpload", MpuParseError(t, w.Body.Bytes()).Code)
			} else {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Contains(t, w.Body.String(), tc.wantBody)
				// Deviation from S3: AWS answers an <Error> document; this is http.Error.
				assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			}
			env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
		})
	}
}

// TestMpuUploadUnknownUploadIDIsNoSuchUpload: an upload id without a session has
// no data key, so there is nothing the part could be sealed with.
func TestMpuUploadUnknownUploadIDIsNoSuchUpload(t *testing.T) {
	env := MpuNewEnv(t)

	url := fmt.Sprintf("/%s/%s?partNumber=1&uploadId=never-created", MpuBucket, MpuKey)
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte("x"))))
	w := httptest.NewRecorder()
	env.upload().Handle(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	doc := MpuParseError(t, w.Body.Bytes())
	assert.Equal(t, "NoSuchUpload", doc.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
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
// the body handed to the backend is sealed segments, never the body the client
// sent, and it is longer by exactly one nonce and one tag per segment.
func TestMpuUploadStoresCiphertextNotPlaintext(t *testing.T) {
	// Parts that the backend will take in the middle of an upload: whole
	// segments, and at or above the 5 MiB minimum. A smaller part can only be
	// the last one, so the proxy holds it instead (see the test below).
	sizes := []int{80 * MpuSegment, 96 * MpuSegment, 160 * MpuSegment}

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
			assert.Len(t, stored, int(MpuStoredPart(size)))
			assert.NotEqual(t, MpuDigest(plaintext), MpuDigest(stored[:size]),
				"plaintext must never reach the backend")
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuUploadShortPartIsHeldUntilComplete: a part that is not a whole number of
// segments cannot be stored where it lies — a chain with a short segment in the
// middle writes cleanly and never reads — so the session keeps it and the client
// is answered without a backend round trip.
func TestMpuUploadShortPartIsHeldUntilComplete(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, MpuSegment - 1, MpuSegment + 1}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)

			w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(size))

			require.Equal(t, http.StatusOK, w.Code)
			// Nothing is stored yet, so there is no backend ETag to hand back —
			// but a client puts the value it gets into its Complete request, and
			// an SDK that finds none there sends an empty one and is refused. The
			// proxy answers with its own value and replaces it with the backend's
			// once the part is stored.
			assert.Regexp(t, `^"[0-9a-f]{8}-\d+"$`, w.Header().Get("ETag"))
			env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
		})
	}
}

// TestMpuUploadDropsBackendEncryptionHeaders records a silent drop on the response
// side: whatever the backend reports about its own encryption of the part, the
// client is told nothing. CompleteMultipartUpload still forwards both headers.
func TestMpuUploadDropsBackendEncryptionHeaders(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{
		ETag:                 aws.String(`"part-1"`),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String("arn:aws:kms:eu-central-1:1:key/abc"),
	}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"part-1"`, w.Header().Get("ETag"))
	assert.Empty(t, w.Header().Get("x-amz-server-side-encryption"))
	assert.Empty(t, w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"))
	env.backend.AssertExpectations(t)
}

func TestMpuUploadWithoutBackendETagStillSucceeds(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart))

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

			w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart))

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
	req := MpuVars(httptest.NewRequest(http.MethodPut, url, bytes.NewReader(MpuPayload(MpuStorablePart))))
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

// TestMpuUploadSealsThePartWhileTheBackendReadsIt: the part is sealed as the
// backend pulls it, not materialised first, and its exact stored length is known
// before a single byte is encrypted (ADR 0024 D2).
func TestMpuUploadSealsThePartWhileTheBackendReadsIt(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	const partSize = MpuStorablePart
	var bodyIsResidentBuffer bool
	var declaredLength, delivered int64
	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		_, bodyIsResidentBuffer = input.Body.(*bytes.Reader)
		declaredLength = aws.ToInt64(input.ContentLength)
		body, err := io.ReadAll(input.Body)
		require.NoError(t, err)
		delivered = int64(len(body))
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(partSize))

	require.Equal(t, http.StatusOK, w.Code)
	assert.False(t, bodyIsResidentBuffer, "the ciphertext must be produced while the backend reads it")
	assert.Equal(t, MpuStoredPart(partSize), declaredLength)
	assert.Equal(t, declaredLength, delivered)
	env.backend.AssertExpectations(t)
}

// TestMpuUploadOutOfOrderPartIsStoredImmediately: a segment is bound to its own
// index, so a part that arrives ahead of its predecessor is sealed and stored
// where it belongs instead of waiting for it.
func TestMpuUploadOutOfOrderPartIsStoredImmediately(t *testing.T) {
	env := MpuNewEnv(t)
	metadata := env.MpuInitiate(t, MpuUploadID)
	stored := env.MpuCaptureParts(t)

	// Equal-sized parts: the proxy places a part at part number times part size,
	// so an object whose parts differ in size has no layout it could store. The
	// contents differ so that a swapped pair would not go unnoticed.
	first, second := MpuPayload(MpuStorablePart), MpuPayload(MpuStorablePart)
	for i := range second {
		second[i] ^= 0xff
	}
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, second).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, first).Code)

	require.Len(t, stored, 2, "both parts reach the backend without waiting for each other")

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	require.Equal(t, http.StatusOK, env.MpuComplete(t, MpuUploadID, 1, 2).Code)

	// The part that arrived first is the one at the higher offset: the chain only
	// reads back if every segment was sealed under the index it is stored at.
	plaintext := env.MpuOpen(t, metadata, MpuChain(stored))
	assert.Equal(t, MpuDigest(append(append([]byte{}, first...), second...)), MpuDigest(plaintext))
	env.backend.AssertExpectations(t)
}

// TestMpuUploadSecondShortPartIsRefused: only the last part of an object may be
// shorter than the part size, and the session already holds one. Accepting a
// second would produce a chain that writes cleanly and never reads.
func TestMpuUploadSecondShortPartIsRefused(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(100)).Code)

	w := env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(200))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "EntityTooSmall", MpuParseError(t, w.Body.Bytes()).Code)
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
			env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)
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

// TestMpuCompleteUnknownUploadIDIsNoSuchUpload: without a session there is no
// part table and no key, so there is nothing to complete.
func TestMpuCompleteUnknownUploadIDIsNoSuchUpload(t *testing.T) {
	env := MpuNewEnv(t)

	w := env.MpuComplete(t, "never-created", 1)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "NoSuchUpload", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// TestMpuCompleteBuildsThePartListItself: the proxy chose where every part starts,
// so the list it sends the backend is its own part table, not the client's — the
// trailer it added itself included, which no client can know about. The client's
// list is still checked against that table, so what a scrambled order costs is
// nothing: the parts are the right ones, only out of order, where AWS answers
// InvalidPartOrder.
func TestMpuCompleteBuildsThePartListItself(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	stored := env.MpuCaptureParts(t)

	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(MpuStorablePart)).Code)

	var forwarded []int32
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.CompleteMultipartUploadInput)
		for _, p := range input.MultipartUpload.Parts {
			forwarded = append(forwarded, aws.ToInt32(p.PartNumber))
		}
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 2, 1)

	assert.Equal(t, http.StatusOK, w.Code, "AWS answers 400 InvalidPartOrder for the scrambled list")
	require.Contains(t, stored, 3, "the trailer is stored as part 3")
	assert.Equal(t, []int32{1, 2, 3}, forwarded,
		"every stored part has to reach the list, the trailer included: a part the list forgets is a part the backend drops")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteForwardsTheStoredETags: the ETags the backend sees are the ones
// the backend itself handed out for the parts the proxy stored, unquoted. What the
// client claims its parts were stored under never reaches it. The trailer's own
// ETag is dropped on the way, the same defect the part list above pins.
func TestMpuCompleteForwardsTheStoredETags(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"stored-1"`)}, nil).Once()
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)
	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"stored-trailer"`)}, nil).Once()

	var forwarded []string
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.CompleteMultipartUploadInput)
		for _, p := range input.MultipartUpload.Parts {
			forwarded = append(forwarded, aws.ToString(p.ETag))
		}
	}).Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"stored-1", "stored-trailer"}, forwarded,
		"Complete forwards the ETags the backend gave the proxy, for the trailer part as much as for the client's")
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteAbortsTheUploadItRefuses: a part table that cannot be stored as a
// chain is refused, and the parts already at the backend must not be left behind
// for a client that was told its upload failed.
func TestMpuCompleteAbortsTheUploadItRefuses(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	// Part 1 never arrives, so the object has a hole where its first segments
	// should be.
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(MpuStorablePart)).Code)

	var aborted *s3.AbortMultipartUploadInput
	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		aborted = args.Get(1).(*s3.AbortMultipartUploadInput)
	}).Return((*s3.AbortMultipartUploadOutput)(nil), errors.New("abort also failed"))

	w := env.MpuComplete(t, MpuUploadID, 2)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "InvalidPart", MpuParseError(t, w.Body.Bytes()).Code)
	require.NotNil(t, aborted, "the upload the proxy refuses must not stay at the backend")
	assert.Equal(t, MpuUploadID, aws.ToString(aborted.UploadId))
	env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
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
			env.MpuCaptureParts(t)
			require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

			env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
				Return((*s3.CompleteMultipartUploadOutput)(nil), tc.backendErr)

			w := env.MpuComplete(t, MpuUploadID, 1)

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := MpuParseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
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
			env.MpuCaptureParts(t)
			require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

			env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
				Return(&s3.CompleteMultipartUploadOutput{
					ETag:     aws.String(`"mpu-etag"`),
					Location: aws.String("https://minio.internal:9000/cov-bucket/cov/key.bin"),
				}, nil)

			req := MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID,
				strings.NewReader(env.MpuCompleteBody(1))))
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
			// The object is complete when the backend says so; no rewrite follows it.
			assert.Equal(t, `"mpu-etag"`, doc.ETag)
			env.backend.AssertExpectations(t)
		})
	}
}

// TestMpuCompleteTrailerFailureIsReportedAsFailure: without the record that closes
// the object nothing can read the chain, so a client told "success" would own an
// object that is lost. The upload is aborted rather than left half written.
func TestMpuCompleteTrailerFailureIsReportedAsFailure(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"stored-1"`)}, nil).Once()
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return((*s3.UploadPartOutput)(nil), MpuAPIError("SlowDown", "Please reduce your request rate")).Once()

	var aborted *s3.AbortMultipartUploadInput
	env.backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		aborted = args.Get(1).(*s3.AbortMultipartUploadInput)
	}).Return(&s3.AbortMultipartUploadOutput{}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "SlowDown", MpuParseError(t, w.Body.Bytes()).Code)
	assert.NotContains(t, w.Body.String(), "CompleteMultipartUploadResult")
	require.NotNil(t, aborted, "the unreadable upload must not stay at the backend")
	env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteForwardsBackendResponseHeaders keeps the completion answer the
// client sees: version id and the backend's own encryption state travel back, and
// the ETag is the one CompleteMultipartUpload returned.
func TestMpuCompleteForwardsBackendResponseHeaders(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{
			ETag:                 aws.String(`"mpu-etag"`),
			VersionId:            aws.String("mpu-version"),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
			SSEKMSKeyId:          aws.String("kms-key"),
		}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"mpu-etag"`, w.Header().Get("ETag"))
	assert.Equal(t, "mpu-version", w.Header().Get("x-amz-version-id"))
	assert.Equal(t, "AES256", w.Header().Get("x-amz-server-side-encryption"))
	assert.Equal(t, "kms-key", w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"))
	// The object's metadata was fixed at CreateMultipartUpload, so completion is
	// the last call: no read-back and no server-side rewrite follow it.
	env.backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
	env.backend.AssertNotCalled(t, "HeadObject", mock.Anything, mock.Anything)
	env.backend.AssertExpectations(t)
}

// Under the exit provider the client-driven multipart upload passes through end
// to end: Create registers no session and attaches no proxy metadata, every part
// is stored as the client sent it, and Complete is built from the client's own
// list because the proxy owns no part table here. Parts that are not whole
// segments are the case that can only work this way - the backend's own rules
// about part sizes are the ones the client meets.
func TestMpuUnderTheExitProviderPassesThrough(t *testing.T) {
	env := MpuNewExitEnv(t)
	metadata := env.MpuInitiate(t, MpuUploadID)
	stored := env.MpuCaptureParts(t)

	first := MpuPayload(1000)
	second := MpuPayload(2000)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, first).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, second).Code)

	var completed *s3.CompleteMultipartUploadInput
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			completed = args.Get(1).(*s3.CompleteMultipartUploadInput)
		}).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	require.Equal(t, http.StatusOK, env.MpuComplete(t, MpuUploadID, 1, 2).Code)

	for key := range metadata {
		assert.NotContains(t, key, "s3ep-", "no proxy metadata may be attached under the exit provider")
	}
	assert.Equal(t, MpuDigest(first), MpuDigest(stored[1]), "the part is stored as the client sent it")
	assert.Equal(t, MpuDigest(second), MpuDigest(stored[2]))

	require.NotNil(t, completed)
	require.NotNil(t, completed.MultipartUpload)
	require.Len(t, completed.MultipartUpload.Parts, 2,
		"the client's list is the object; the proxy adds no record of its own")
	assert.Equal(t, int32(1), aws.ToInt32(completed.MultipartUpload.Parts[0].PartNumber))
	assert.Equal(t, int32(2), aws.ToInt32(completed.MultipartUpload.Parts[1].PartNumber))
	env.backend.AssertExpectations(t)
}

// TestMpuCompleteRefusesAPartListThatIsNotTheUpload: the object is built from the
// proxy's part table, but a client whose list disagrees with that table is
// describing a different upload and is told so instead of being handed an object
// it did not ask for (ADR 0011 D6). The upload survives the refusal, as it does at
// S3, so the client can complete again with the right list.
func TestMpuCompleteRefusesAPartListThatIsNotTheUpload(t *testing.T) {
	cases := []struct {
		name string
		// list turns the correct completion document into the broken one.
		list func(env *MpuEnv) string
	}{
		{
			name: "a part that was uploaded is left out",
			list: func(env *MpuEnv) string { return env.MpuCompleteBody(1) },
		},
		{
			name: "a part that was never uploaded is listed",
			list: func(env *MpuEnv) string { return env.MpuCompleteBody(1, 2, 3) },
		},
		{
			name: "a part carries an entity tag it was not stored under",
			list: func(env *MpuEnv) string {
				env.etags[2] = "00000000000000000000000000000000"
				return env.MpuCompleteBody(1, 2)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := MpuNewEnv(t)
			env.MpuInitiate(t, MpuUploadID)
			env.MpuCaptureParts(t)

			require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)
			require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(MpuStorablePart)).Code)

			req := MpuVars(httptest.NewRequest(http.MethodPost,
				"/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, strings.NewReader(tc.list(env))))
			w := httptest.NewRecorder()
			env.complete().Handle(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, "InvalidPart", MpuParseError(t, w.Body.Bytes()).Code)
			env.backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
			env.backend.AssertNotCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)

			// The session is still there, and the same parts complete once the list
			// describes them.
			_, alive := env.enc.SegmentedSession(MpuUploadID)
			assert.True(t, alive, "a refused completion list must not destroy the upload")
		})
	}
}

// TestMpuCompleteStoresAChainThatReadsBack is the round trip this format exists
// for: whole-segment parts and one short last part, sealed independently, form one
// object that opens with the metadata the upload was created with.
func TestMpuCompleteStoresAChainThatReadsBack(t *testing.T) {
	env := MpuNewEnv(t)
	metadata := env.MpuInitiate(t, MpuUploadID)
	stored := env.MpuCaptureParts(t)

	parts := [][]byte{MpuPayload(MpuStorablePart), MpuPayload(MpuStorablePart), MpuPayload(1000)}
	for i := range parts[1] {
		parts[1][i] ^= 0xff
	}
	var plaintext []byte
	for number, part := range parts {
		require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, number+1, part).Code)
		plaintext = append(plaintext, part...)
	}
	// The short last part is held back: it can only be sealed once the trailer
	// behind it is known.
	require.Len(t, stored, 2)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	require.Equal(t, http.StatusOK, env.MpuComplete(t, MpuUploadID, 1, 2, 3).Code)

	require.Len(t, stored, 3, "the held part is stored with the trailer riding on it")
	chain := MpuChain(stored)
	assert.Equal(t, int64(len(chain)), func() int64 {
		size, err := dataencryption.CiphertextSize(int64(len(plaintext)))
		require.NoError(t, err)
		return size
	}(), "the stored object is exactly the length the format prescribes")
	assert.Equal(t, MpuDigest(plaintext), MpuDigest(env.MpuOpen(t, metadata, chain)))
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
	_, live := env.enc.SegmentedSession(MpuUploadID)
	assert.False(t, live, "the encryption session must not outlive the abort")

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
	env.MpuCaptureParts(t)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

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
	h.GetCreateHandler().Handle(createW, MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey+"?uploads", nil)))
	require.Equal(t, http.StatusOK, createW.Code)

	uploadW := httptest.NewRecorder()
	h.GetUploadHandler().Handle(uploadW, MpuVars(httptest.NewRequest(http.MethodPut, "/"+MpuBucket+"/"+MpuKey, nil)))
	assert.Equal(t, http.StatusBadRequest, uploadW.Code)

	completeW := httptest.NewRecorder()
	h.GetCompleteHandler().Handle(completeW, MpuVars(httptest.NewRequest(http.MethodPost, "/"+MpuBucket+"/"+MpuKey, nil)))
	assert.Equal(t, http.StatusInternalServerError, completeW.Code)

	abortW := httptest.NewRecorder()
	h.GetAbortHandler().Handle(abortW, MpuVars(httptest.NewRequest(http.MethodDelete, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil)))
	assert.Equal(t, http.StatusNoContent, abortW.Code)

	listPartsW := httptest.NewRecorder()
	h.GetListHandler().HandleListParts(listPartsW, MpuVars(httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"/"+MpuKey+"?uploadId="+MpuUploadID, nil)))
	assert.Equal(t, http.StatusOK, listPartsW.Code)
	assert.Contains(t, listPartsW.Body.String(), "ListPartsResult")

	listUploadsW := httptest.NewRecorder()
	h.GetListHandler().HandleListMultipartUploads(listUploadsW, mux.SetURLVars(
		httptest.NewRequest(http.MethodGet, "/"+MpuBucket+"?uploads", nil),
		map[string]string{"bucket": MpuBucket}))
	assert.Equal(t, http.StatusNotImplemented, listUploadsW.Code)

	env.backend.AssertExpectations(t)
}

// TestMpuUploadOversizedShortPartNeverReachesTheBackend: a part the session cannot
// hold answers SlowDown and stores nothing. The buffer is what an operator budgets
// per upload for the one part that has to wait for Complete, and running out of it
// is back pressure an SDK retries, not a refusal of the upload (ADR 0011 D5).
func TestMpuUploadOversizedShortPartNeverReachesTheBackend(t *testing.T) {
	env := MpuNewEnv(t)
	// Tiny on purpose: the refusal is what is under test, not the megabytes.
	env.cfg.Optimizations.MultipartShortPartBufferSize = 64
	env.MpuInitiate(t, MpuUploadID)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(128))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "SlowDown", MpuParseError(t, w.Body.Bytes()).Code)
	env.backend.AssertNotCalled(t, "UploadPart", mock.Anything, mock.Anything)

	// The upload survives it: the same part sent again once there is room is taken.
	env.cfg.Optimizations.MultipartShortPartBufferSize = 5 * 1024 * 1024
	assert.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(128)).Code)
}

// TestMpuUploadSurvivesSessionVanishingMidFlight: a concurrent abort removes the
// session while the part is at the backend. The part is stored, so the client is
// told so; only the local bookkeeping is lost.
func TestMpuUploadSurvivesSessionVanishingMidFlight(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)

	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		env.enc.CloseSegmentedSession(MpuUploadID)
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"part-1"`)}, nil)

	w := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"part-1"`, w.Header().Get("ETag"))
	env.backend.AssertExpectations(t)
}

// TestMpuUploadRetryOfAPartIsSealedAgain: S3 lets a client re-upload a part, and
// every AWS SDK retries a part whose response it did not like. A segment is bound
// to its own index, so the retry is simply sealed again — with fresh nonces — and
// stored over the first attempt.
func TestMpuUploadRetryOfAPartIsSealedAgain(t *testing.T) {
	env := MpuNewEnv(t)
	metadata := env.MpuInitiate(t, MpuUploadID)

	stored := make(map[int][][]byte)
	env.backend.On("UploadPart", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		input := args.Get(1).(*s3.UploadPartInput)
		body, err := io.ReadAll(input.Body)
		require.NoError(t, err)
		number := int(aws.ToInt32(input.PartNumber))
		stored[number] = append(stored[number], body)
	}).Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)

	part := MpuPayload(MpuStorablePart)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, part).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, part).Code)

	require.Len(t, stored[1], 2)
	assert.NotEqual(t, MpuDigest(stored[1][0]), MpuDigest(stored[1][1]), "every sealing draws its own nonces")

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)
	require.Equal(t, http.StatusOK, env.MpuComplete(t, MpuUploadID, 1).Code)
	require.Len(t, stored[2], 1, "the trailer closes the object as a part of its own")

	// Whichever attempt the backend kept, the object reads back.
	for _, attempt := range stored[1] {
		chain := append(append([]byte{}, attempt...), stored[2][0]...)
		assert.Equal(t, MpuDigest(part), MpuDigest(env.MpuOpen(t, metadata, chain)))
	}
	env.backend.AssertExpectations(t)
}
