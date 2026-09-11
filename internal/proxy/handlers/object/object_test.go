package object

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 - Content-MD5 is the digest S3 defines for a multi-object delete
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
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
				"s3ep-encrypted-dek":   "value",
				"s3ep-dek-algorithm":   dataencryption.FormatID,
				"s3ep-kek-fingerprint": "fingerprint",
				"s3ep-kek-algorithm":   "aes",
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

// getSegmentSize is the part size of the multipart producer, not the segment of
// the storage format: that one is a constant of the format.
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
		s3Backend:   backend,
		logger:      entry,
		errorWriter: response.NewErrorWriter(entry),
		// Every body this handler reads goes through the parser, which is also
		// where a client checksum is verified (ADR 0012).
		requestParser:  request.NewParser(entry, &config.Config{}),
		metadataPrefix: "s3ep-",
	}
}

// newEncryptingTestHandler builds a fully wired handler with a real AES provider,
// a two-segment part size and a single upload worker, so the multipart producer
// is deterministic in a unit test. The part size is a whole number of segments
// because a part that is not one can only be the last part of an object.
func newEncryptingTestHandler(t *testing.T, backend *MockS3Backend) *Handler {
	t.Helper()
	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     &prefix,
			Providers: []config.EncryptionProvider{{
				Alias: "test-aes",
				Type:  "aes",
				Config: map[string]interface{}{
					"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
				},
			}},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 2 * dataencryption.SegmentSize
	cfg.Optimizations.MultipartUploadConcurrency = 1

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// storeSegmentedObject seals a plaintext through the write path and returns what
// the backend would hold for it: the stored bytes and the object metadata.
func storeSegmentedObject(t *testing.T, h *Handler, key string, plaintext []byte) ([]byte, map[string]string) {
	t.Helper()
	write, err := h.encryptionMgr.NewSegmentedWrite(key, bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)

	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)
	require.Equal(t, write.ContentLength, int64(len(stored)),
		"the declared stored length must match what the sealer produces")
	require.NotEqual(t, plaintext, stored, "the fixture handed the backend plaintext")
	return stored, write.Metadata
}

// plaintextDigest keeps large-payload comparisons out of the failure output.
func plaintextDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testPayload builds a deterministic payload of n bytes.
func testPayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
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
// What the proxy will read at all.
// ---------------------------------------------------------------------------

// An object is readable only when its metadata names the format this proxy
// writes and carries the wrapped key that opens it. Anything else is refused
// with 403 InvalidObjectState: under an encrypting provider there is no
// pass-through, because handing a client bytes nobody authenticated is the one
// answer that must never happen (ADR 0003).
func TestForeignObjectIsRefusedOnGetAndHead(t *testing.T) {
	// A stored length a real chain could have, so the refusal is decided by the
	// metadata rather than by the length arithmetic.
	storedLen, err := dataencryption.CiphertextSize(4096)
	require.NoError(t, err)

	cases := map[string]map[string]string{
		"no metadata at all": nil,
		"user metadata only": {"user-key": "user-value"},
		"the previous format": {
			"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm": "aes-ctr",
			"s3ep-aes-iv":        "AAAAAAAAAAAAAAAAAAAAAA==",
		},
		"this format without a wrapped key": {"s3ep-dek-algorithm": dataencryption.FormatID},
	}

	for name, metadata := range cases {
		t.Run(name+"/GET", func(t *testing.T) {
			backend := new(MockS3Backend)
			h := newEncryptingTestHandler(t, backend)
			backend.On("GetObject", mock.Anything, mock.Anything).
				Return(&s3.GetObjectOutput{
					Body:          io.NopCloser(bytes.NewReader(testPayload(int(storedLen)))),
					ContentLength: aws.Int64(storedLen),
					Metadata:      metadata,
				}, nil)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test-bucket/test-key", nil)
			h.handleGetObject(rr, req, "test-bucket", "test-key")

			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.Contains(t, rr.Body.String(), "InvalidObjectState")
		})

		t.Run(name+"/HEAD", func(t *testing.T) {
			backend := new(MockS3Backend)
			h := newEncryptingTestHandler(t, backend)
			backend.On("HeadObject", mock.Anything, mock.Anything).
				Return(&s3.HeadObjectOutput{
					ContentLength: aws.Int64(storedLen),
					Metadata:      metadata,
				}, nil)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodHead, "/test-bucket/test-key", nil)
			h.handleHeadObject(rr, req, "test-bucket", "test-key")

			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.Contains(t, rr.Body.String(), "InvalidObjectState")
		})
	}
}

// ---------------------------------------------------------------------------
// GET / HEAD: versionId forwarding, entity headers, no backend checksums.
// ---------------------------------------------------------------------------

func TestHandleGetObject_VersionIDAndResponseHeaders(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	// More than one segment, so what the backend holds is a chain rather than a
	// single sealed record.
	payload := testPayload(dataencryption.SegmentSize + 4096)
	stored, metadata := storeSegmentedObject(t, h, "test-key", payload)
	metadata["user"] = "value"

	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(&s3.GetObjectOutput{
			Body:               io.NopCloser(bytes.NewReader(stored)),
			ContentLength:      aws.Int64(int64(len(stored))),
			ETag:               aws.String(`"ciphertext-etag"`),
			VersionId:          aws.String("version-42"),
			ContentEncoding:    aws.String("gzip"),
			ContentDisposition: aws.String(`attachment; filename="x.txt"`),
			ContentLanguage:    aws.String("de-DE"),
			CacheControl:       aws.String("max-age=99"),
			Metadata:           metadata,
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

	// The client reads plaintext, and is told the plaintext length rather than
	// the stored one the backend reported.
	assert.Equal(t, plaintextDigest(payload), plaintextDigest(rr.Body.Bytes()))
	assert.Equal(t, strconv.Itoa(len(payload)), rr.Header().Get("Content-Length"))

	// The proxy's own metadata never reaches the client; the client's own does.
	assert.Equal(t, "value", rr.Header().Get("x-amz-meta-user"))
	for name := range rr.Result().Header {
		assert.Falsef(t, strings.HasPrefix(strings.ToLower(name), "x-amz-meta-s3ep-"),
			"response leaked the encryption metadata header %s", name)
	}
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

func TestHandleHeadObject_VersionIDAndPlaintextLength(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	payload := testPayload(dataencryption.SegmentSize + 4096)
	stored, metadata := storeSegmentedObject(t, h, "test-key", payload)

	var captured *s3.HeadObjectInput
	backend.On("HeadObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.HeadObjectInput) }).
		Return(&s3.HeadObjectOutput{
			ContentLength:  aws.Int64(int64(len(stored))),
			ETag:           aws.String(`"ciphertext-etag"`),
			VersionId:      aws.String("version-42"),
			Metadata:       metadata,
			ChecksumSHA256: aws.String("AAAAAA=="),
		}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/test-bucket/test-key?versionId=version-42", nil)
	h.handleHeadObject(rr, req, "test-bucket", "test-key")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "version-42", aws.ToString(captured.VersionId), "HEAD must address the requested version")
	assert.Equal(t, "version-42", rr.Header().Get("x-amz-version-id"))

	// The stored length converts to the plaintext length without a round trip. A
	// HEAD that reported the stored one would contradict the GET that follows it
	// (ADR 0010).
	assert.Equal(t, strconv.Itoa(len(payload)), rr.Header().Get("Content-Length"))
	assertNoChecksumHeaders(t, rr.Result().Header)
}

// A plaintext that is an exact multiple of the producer's part size used to be
// stored without its trailer: the last buffer filled exactly, so it was sealed
// as a middle part, and the loop then ended on a clean EOF without closing the
// chain. The upload answered 200 and every read of the object afterwards failed
// authentication. The trailer is a part of its own in that layout.
func TestPutObjectAutoMultipart_ExactMultipleOfThePartSizeKeepsTheTrailer(t *testing.T) {
	partSize := int64(2 * dataencryption.SegmentSize)

	for name, size := range map[string]int64{
		"one_whole_part":    partSize,
		"two_whole_parts":   2 * partSize,
		"two_parts_plus_7b": 2*partSize + 7,
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := newEncryptingTestHandler(t, backend)

			var mu sync.Mutex
			parts := map[int32][]byte{}
			var createInput *s3.CreateMultipartUploadInput
			backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
				Run(func(a mock.Arguments) { createInput = a.Get(1).(*s3.CreateMultipartUploadInput) }).
				Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u")}, nil)
			backend.On("UploadPart", mock.Anything, mock.Anything).
				Run(func(a mock.Arguments) {
					in := a.Get(1).(*s3.UploadPartInput)
					body, err := io.ReadAll(in.Body)
					require.NoError(t, err)
					mu.Lock()
					parts[aws.ToInt32(in.PartNumber)] = body
					mu.Unlock()
				}).
				Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
			backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
				Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"e"`)}, nil)

			payload := testPayload(int(size))
			req := httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(payload))
			rr := httptest.NewRecorder()
			objCallAutoMultipart(t, h, rr, req, "b", "k")
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			var stored []byte
			for i := int32(1); i <= int32(len(parts)); i++ {
				stored = append(stored, parts[i]...)
			}
			expected, err := dataencryption.CiphertextSize(size)
			require.NoError(t, err)
			require.Equal(t, expected, int64(len(stored)),
				"the stored object must carry every segment and the trailer")

			// The proof is the read: the trailer is what authenticates the
			// object's length, and Close is where it is checked.
			rd, err := h.encryptionMgr.OpenSegmented("k", createInput.Metadata,
				io.NopCloser(bytes.NewReader(stored)))
			require.NoError(t, err)
			got, err := io.ReadAll(rd)
			require.NoError(t, err)
			require.NoError(t, rd.Close())
			assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(got))
		})
	}
}

// A body that stops early must never be committed, and on the path where no
// plaintext length was declared the declared-length guard cannot catch it. The
// producer used to fold io.ErrUnexpectedEOF into "the object ended here", so a
// truncated upload was sealed with its trailer and committed: a silently short
// object that passes every later verification (ADR 0012 D12).
func TestPutObjectAutoMultipart_ATruncatedStreamIsNotCommitted(t *testing.T) {
	for name, srcErr := range map[string]error{
		"unexpected_eof":  io.ErrUnexpectedEOF,
		"framing_failure": errors.New("aws-chunked: invalid chunk size"),
		"wrapped_eof":     fmt.Errorf("aws-chunked: read chunk header: %w", io.EOF),
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := newEncryptingTestHandler(t, backend)

			backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
				Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("u")}, nil)
			backend.On("UploadPart", mock.Anything, mock.Anything).
				Run(func(a mock.Arguments) {
					_, _ = io.ReadAll(a.Get(1).(*s3.UploadPartInput).Body)
				}).
				Return(&s3.UploadPartOutput{ETag: aws.String(`"p"`)}, nil)
			backend.On("AbortMultipartUpload", mock.Anything, mock.Anything).
				Return(&s3.AbortMultipartUploadOutput{}, nil)

			// Two full parts, then the stream stops without ever reaching EOF.
			body := &truncatingReader{
				data: testPayload(2 * 2 * dataencryption.SegmentSize),
				err:  srcErr,
			}
			req := httptest.NewRequest(http.MethodPut, "/b/k", http.NoBody)
			req.Body = io.NopCloser(body)
			req.ContentLength = -1

			rr := httptest.NewRecorder()
			objCallAutoMultipart(t, h, rr, req, "b", "k")

			assert.NotEqual(t, http.StatusOK, rr.Code,
				"a stream that stopped early must not be committed")
			backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
			backend.AssertCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
		})
	}
}

// objAWSChunked wraps payload in the unsigned aws-chunked framing an SDK emits.
func objAWSChunked(payload []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%x\r\n", len(payload))
	buf.Write(payload)
	buf.WriteString("\r\n0\r\n\r\n")
	return buf.Bytes()
}

// truncatingReader delivers its data and then fails instead of reporting EOF,
// the way a body whose framing ended early does.
type truncatingReader struct {
	data []byte
	off  int
	err  error
}

func (r *truncatingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// ---------------------------------------------------------------------------
// Client checksums never reach the backend.
// ---------------------------------------------------------------------------

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
	sum := md5.Sum([]byte(body)) // #nosec G401 - Content-MD5 is the digest S3 defines here
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))

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

	// Retention and legal hold left this list on 2026-09-11: they are passthrough
	// now (ADR 0007 D4), and only a verb they do not define answers 501.
	cases := map[string]func(w http.ResponseWriter){
		"legal_hold_delete": func(w http.ResponseWriter) {
			h.handleObjectLegalHold(w, httptest.NewRequest(http.MethodDelete, "/b/k?legal-hold", nil), "b", "k")
		},
		"retention_delete": func(w http.ResponseWriter) {
			h.handleObjectRetention(w, httptest.NewRequest(http.MethodDelete, "/b/k?retention", nil), "b", "k")
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
// The multipart producer: cleanup that must outlive the request, the truncation
// guard, and the metadata that makes the stored chain readable.
// ---------------------------------------------------------------------------

func TestPutObjectAutoMultipart_AbortOutlivesClientDisconnect(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)

	body := testPayload(4096)
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
	objCallAutoMultipart(t, h, rr, req, "test-bucket", "test-key")

	backend.AssertCalled(t, "UploadPart", mock.Anything, mock.Anything)
	require.True(t, aborted, "the abort must reach the backend after a client disconnect")
	assert.NoError(t, abortCtxErr, "the abort must not inherit the cancelled request context")
	assert.True(t, abortHasDeadline, "the detached cleanup context must stay bounded")
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// A body shorter than the declared length is a producer error, not a clean end of
// stream. Committing it stores a truncated object whose trailer seals exactly
// what arrived, so it reads back cleanly and nothing ever reports the loss.
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

	body := testPayload(1000)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(body))
	req.ContentLength = 4096 // the client promised four times what it sent

	rr := httptest.NewRecorder()
	objCallAutoMultipart(t, h, rr, req, "test-bucket", "test-key")

	assert.Equal(t, http.StatusInternalServerError, rr.Code,
		"a body shorter than the declared length must fail the upload, not report success")
	assert.Contains(t, rr.Body.String(), "declared 4096",
		"the upload must fail on the length guard, not on something else on the way")
	backend.AssertCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "CompleteMultipartUpload", mock.Anything, mock.Anything)
}

// The whole metadata set exists before the first byte is sent, so it rides on
// CreateMultipartUpload and no rewrite follows the completion. The absence of
// that rewrite is the point: the ETag the client is told is the one
// CompleteMultipartUpload returned, and no second write can undo the metadata.
func TestPutObjectAutoMultipart_MetadataRidesOnCreateWithoutARewrite(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	var createInput *s3.CreateMultipartUploadInput
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createInput = args.Get(1).(*s3.CreateMultipartUploadInput) }).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil)
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{
			ETag:      aws.String(`"mpu-etag-1"`),
			VersionId: aws.String("mpu-version"),
		}, nil)

	body := testPayload(4096)
	// The request declares aws-chunked, so it has to carry that framing: the
	// decoder is not configurable and always strips it.
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key",
		bytes.NewReader(objAWSChunked(body)))
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("Cache-Control", "max-age=99")
	req.Header.Set("Content-Disposition", `attachment; filename="x.txt"`)
	req.Header.Set("Content-Encoding", "aws-chunked,gzip")
	req.Header.Set("Content-Language", "de-DE")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Amz-Meta-User", "value")

	rr := httptest.NewRecorder()
	objCallAutoMultipart(t, h, rr, req, "test-bucket", "test-key")

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, createInput)

	assert.Equal(t, "text/plain", aws.ToString(createInput.ContentType))
	assert.Equal(t, "max-age=99", aws.ToString(createInput.CacheControl))
	assert.Equal(t, `attachment; filename="x.txt"`, aws.ToString(createInput.ContentDisposition))
	assert.Equal(t, "gzip", aws.ToString(createInput.ContentEncoding), "aws-chunked describes the request framing")
	assert.Equal(t, "de-DE", aws.ToString(createInput.ContentLanguage))

	assert.Equal(t, dataencryption.FormatID, createInput.Metadata["s3ep-dek-algorithm"])
	assert.NotEmpty(t, createInput.Metadata["s3ep-encrypted-dek"])
	assert.NotEmpty(t, createInput.Metadata["s3ep-kek-fingerprint"])
	assert.NotEmpty(t, createInput.Metadata["s3ep-kek-algorithm"])
	assert.Equal(t, "value", createInput.Metadata["user"], "the client's own metadata travels with the object")

	// Four keys and no more: this format has no per-object IV and no separate
	// integrity value, so a fifth key here means one of them came back.
	proxyKeys := make([]string, 0, 4)
	for key := range createInput.Metadata {
		if strings.HasPrefix(key, "s3ep-") {
			proxyKeys = append(proxyKeys, key)
		}
	}
	sort.Strings(proxyKeys)
	assert.Equal(t, []string{
		"s3ep-dek-algorithm", "s3ep-encrypted-dek", "s3ep-kek-algorithm", "s3ep-kek-fingerprint",
	}, proxyKeys)

	assert.Equal(t, `"mpu-etag-1"`, rr.Header().Get("ETag"))
	assert.Equal(t, "mpu-version", rr.Header().Get("x-amz-version-id"))
	backend.AssertNotCalled(t, "CopyObject", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "AbortMultipartUpload", mock.Anything, mock.Anything)
}

// The parts the producer sends are one chain: concatenated in part order they
// are exactly what a GET of the same object reads back as plaintext, under the
// metadata CreateMultipartUpload carried.
func TestPutObjectAutoMultipart_StoredChainReadsBackAsPlaintext(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	var createInput *s3.CreateMultipartUploadInput
	backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createInput = args.Get(1).(*s3.CreateMultipartUploadInput) }).
		Return(&s3.CreateMultipartUploadOutput{UploadId: aws.String("auto-upload-id")}, nil)

	parts := make(map[int][]byte)
	backend.On("UploadPart", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			input := args.Get(1).(*s3.UploadPartInput)
			// The body seals straight out of the producer's buffer, which goes
			// back to the free list as soon as this call returns: read it here or
			// never.
			stored, err := io.ReadAll(input.Body)
			require.NoError(t, err)
			require.Equal(t, aws.ToInt64(input.ContentLength), int64(len(stored)),
				"a part's declared length must match the bytes it sends")
			parts[int(aws.ToInt32(input.PartNumber))] = stored
		}).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil)
	backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag-1"`)}, nil)

	// Two full parts and a partial one, so the object ends inside a segment and
	// the trailer rides on a part that is not full.
	payload := testPayload(2*int(h.getSegmentSize()) + 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/test-key", bytes.NewReader(payload))

	rr := httptest.NewRecorder()
	objCallAutoMultipart(t, h, rr, req, "test-bucket", "test-key")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, parts, 3)

	var stored []byte
	for partNumber := 1; partNumber <= len(parts); partNumber++ {
		stored = append(stored, parts[partNumber]...)
	}

	backend.On("GetObject", mock.Anything, mock.Anything).
		Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(stored)),
			ContentLength: aws.Int64(int64(len(stored))),
			Metadata:      createInput.Metadata,
		}, nil)

	getRR := httptest.NewRecorder()
	h.handleGetObject(getRR, httptest.NewRequest(http.MethodGet, "/test-bucket/test-key", nil),
		"test-bucket", "test-key")

	require.Equal(t, http.StatusOK, getRR.Code)
	assert.Equal(t, plaintextDigest(payload), plaintextDigest(getRR.Body.Bytes()))
	assert.Equal(t, strconv.Itoa(len(payload)), getRR.Header().Get("Content-Length"))
}

// objCallAutoMultipart drives the producer the way handlePutObject does: the
// upload headers come from the request, not from a literal at the call site.
func objCallAutoMultipart(
	t *testing.T, h *Handler, rr http.ResponseWriter, req *http.Request, bucket, key string,
) {
	t.Helper()
	entity, attrs, err := ReadUploadHeaders(req)
	require.NoError(t, err)
	userMetadata, err := h.userMetadataFromRequest(req)
	require.NoError(t, err)
	h.putObjectAutoMultipart(rr, req, bucket, key, entity, attrs, userMetadata)
}
