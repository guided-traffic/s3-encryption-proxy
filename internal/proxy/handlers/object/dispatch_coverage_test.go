package object

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
)

// ---------------------------------------------------------------------------
// Fixtures. Everything here goes through the exported entry points, so what is
// asserted is the client contract - status, S3 error code, headers, body and
// which backend call the request turned into. None of it depends on the storage
// format, so ticket 013 does not touch this file.
// ---------------------------------------------------------------------------

const ObjMiscaesKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

// ObjMiscnewHandler wires a handler with a real AES provider, the default
// metadata prefix and strict integrity verification.
func ObjMiscnewHandler(t *testing.T, backend *MockS3Backend) *Handler {
	t.Helper()
	return ObjMiscnewHandlerWithPrefix(t, backend, "s3ep-")
}

// ObjMiscnewHandlerWithPrefix is the same but lets a test choose the configured
// metadata_key_prefix, which is what decides how metadata is filtered.
func ObjMiscnewHandlerWithPrefix(t *testing.T, backend *MockS3Backend, prefix string) *Handler {
	t.Helper()
	p := prefix
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			MetadataKeyPrefix:     &p,
			IntegrityVerification: config.HMACVerificationStrict,
			Providers: []config.EncryptionProvider{{
				Alias:  "test-aes",
				Type:   "aes",
				Config: map[string]interface{}{"aes_key": ObjMiscaesKey},
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

// ObjMiscdo drives a request through Handler.Handle, so the query-parameter
// routing and the method switch are part of what is under test.
func ObjMiscdo(h *Handler, req *http.Request, bucket, key string) *httptest.ResponseRecorder {
	req = mux.SetURLVars(req, map[string]string{"bucket": bucket, "key": key})
	rr := httptest.NewRecorder()
	h.Handle(rr, req)
	return rr
}

// ObjMiscdoFunc drives a request through one of the exported wrappers, which is
// how the router reaches the sub-resource handlers.
func ObjMiscdoFunc(fn http.HandlerFunc, req *http.Request, vars map[string]string) *httptest.ResponseRecorder {
	req = mux.SetURLVars(req, vars)
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

// ObjMiscerrorDoc is the S3 <Error> document every refusal has to be.
type ObjMiscerrorDoc struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource"`
}

func ObjMiscparseError(t *testing.T, body []byte) ObjMiscerrorDoc {
	t.Helper()
	var doc ObjMiscerrorDoc
	require.NoError(t, xml.Unmarshal(body, &doc), "a refusal must be a parseable S3 error document")
	return doc
}

// ObjMiscassertNotImplemented is the shape every refused sub-resource has to
// have: 501, an XML content type and Code=NotImplemented naming the operation.
func ObjMiscassertNotImplemented(t *testing.T, rr *httptest.ResponseRecorder, operation string) {
	t.Helper()
	assert.Equal(t, http.StatusNotImplemented, rr.Code)
	assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
	doc := ObjMiscparseError(t, rr.Body.Bytes())
	assert.Equal(t, "NotImplemented", doc.Code)
	assert.Equal(t, operation, doc.Resource)
	assert.Equal(t, operation+" operation is not yet implemented", doc.Message)
}

// ---------------------------------------------------------------------------
// Handler.Handle: the method dispatch.
// ---------------------------------------------------------------------------

// Each supported method has to reach its own backend call, and nothing else.
func TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("GetObject", mock.Anything, mock.MatchedBy(func(in *s3.GetObjectInput) bool {
			return aws.ToString(in.Bucket) == "b" && aws.ToString(in.Key) == "k"
		})).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader("plain")),
			ContentLength: aws.Int64(5),
		}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "plain", rr.Body.String())
		backend.AssertExpectations(t)
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})

	t.Run("HEAD", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("HeadObject", mock.Anything, mock.Anything).
			Return(&s3.HeadObjectOutput{ContentLength: aws.Int64(7), ETag: aws.String(`"e"`)}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "7", rr.Header().Get("Content-Length"))
		assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
		assert.Empty(t, rr.Body.String(), "HEAD must not carry a body")
		backend.AssertExpectations(t)
	})

	t.Run("PUT", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		var stored *s3.PutObjectInput
		backend.On("PutObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { stored = args.Get(1).(*s3.PutObjectInput) }).
			Return(&s3.PutObjectOutput{ETag: aws.String(`"stored"`)}, nil)

		body := []byte("the plaintext nobody may see at the backend")
		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodPut, "/b/k", bytes.NewReader(body)), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, stored)
		uploaded, err := io.ReadAll(stored.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(uploaded), "plaintext",
			"the bytes handed to the backend must not be the plaintext")
		backend.AssertExpectations(t)
	})

	t.Run("DELETE", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(in *s3.DeleteObjectInput) bool {
			return aws.ToString(in.Bucket) == "b" && aws.ToString(in.Key) == "k" && in.VersionId == nil
		})).Return(&s3.DeleteObjectOutput{}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Empty(t, rr.Body.String())
		backend.AssertExpectations(t)
	})
}

// DEFECT (minor, reported): a method the object resource does not support is
// answered 501 NotImplemented. AWS answers 405 MethodNotAllowed with
// Code=MethodNotAllowed and an Allow header. A client that retries on 501 but
// not on 405 - or the other way round - reads the wrong instruction.
// The router registers POST on this handler, so POST is the live case; the rest
// are here because Handle is exported and callable with any method.
func TestObjMiscHandleUnsupportedMethodIsRefusedNotSilently200(t *testing.T) {
	for _, method := range []string{
		http.MethodPost, http.MethodPatch, http.MethodOptions, http.MethodTrace, http.MethodConnect,
	} {
		t.Run(method, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			rr := ObjMiscdo(h, httptest.NewRequest(method, "/b/k", nil), "b", "k")

			// The load-bearing assertion: it is not a 200 and no backend call happened.
			assert.NotEqual(t, http.StatusOK, rr.Code)
			assert.Equal(t, 0, len(backend.Calls), "an unsupported method must not reach the backend")

			ObjMiscassertNotImplemented(t, rr, "Object_"+method)
			// Pins the deviation from AWS so a later fix shows up here.
			assert.NotEqual(t, http.StatusMethodNotAllowed, rr.Code,
				"AWS answers 405 MethodNotAllowed here; the proxy answers 501")
			assert.Empty(t, rr.Header().Get("Allow"), "no Allow header is offered either")
		})
	}
}

// DEFECT (major, reported): Handler.Handle only recognises acl, tagging and
// attributes. Every other object sub-resource is routed by HTTP method in
// router.go, so a sub-resource request with a method that route does not carry
// falls through to the base object operation - the same class of bug that made
// "DELETE /bucket?encryption" delete the bucket, still live for objects.
// DELETE /bucket/key?legal-hold deletes the object; PUT /bucket/key?restore
// overwrites it with the restore request document.
func TestObjMiscHandleFallsThroughUnknownSubResourcesToTheBaseOperation(t *testing.T) {
	t.Run("DELETE with an unrouted sub-resource deletes the object", func(t *testing.T) {
		for _, sub := range []string{"legal-hold", "retention", "torrent", "restore", "select", "uploads"} {
			t.Run(sub, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjMiscnewHandler(t, backend)
				backend.On("DeleteObject", mock.Anything, mock.Anything).
					Return(&s3.DeleteObjectOutput{}, nil)

				rr := ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k?"+sub, nil), "b", "k")

				assert.Equal(t, http.StatusNoContent, rr.Code)
				backend.AssertCalled(t, "DeleteObject", mock.Anything, mock.Anything)
			})
		}
	})

	t.Run("PUT ?restore stores the restore document as the object", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		var stored *s3.PutObjectInput
		backend.On("PutObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { stored = args.Get(1).(*s3.PutObjectInput) }).
			Return(&s3.PutObjectOutput{ETag: aws.String(`"e"`)}, nil)

		doc := `<RestoreRequest><Days>1</Days></RestoreRequest>`
		req := httptest.NewRequest(http.MethodPut, "/b/k?restore", strings.NewReader(doc))
		rr := ObjMiscdo(h, req, "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, stored, "the restore request was stored as object content")
	})
}

// ---------------------------------------------------------------------------
// Handler.Handle: the query-parameter routing.
// ---------------------------------------------------------------------------

// ?acl wins over the method switch, so even a method the router never sends
// here is answered by the ACL handler rather than by PutObject or DeleteObject.
func TestObjMiscHandleRoutesACLToTheACLHandler(t *testing.T) {
	cases := map[string]struct{ method, operation string }{
		"GET":    {http.MethodGet, "GetObjectACL"},
		"PUT":    {http.MethodPut, "PutObjectACL"},
		"DELETE": {http.MethodDelete, "ObjectACL_DELETE"},
		"POST":   {http.MethodPost, "ObjectACL_POST"},
		"HEAD":   {http.MethodHead, "ObjectACL_HEAD"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			rr := ObjMiscdo(h, httptest.NewRequest(tc.method, "/b/k?acl", nil), "b", "k")

			ObjMiscassertNotImplemented(t, rr, tc.operation)
			assert.Equal(t, 0, len(backend.Calls), "?acl must never reach the backend")
		})
	}
}

// An ?acl with a value routes the same way: mux matches on presence.
func TestObjMiscHandleRoutesACLWithAValue(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?acl=public-read", nil), "b", "k")

	ObjMiscassertNotImplemented(t, rr, "GetObjectACL")
	assert.Equal(t, 0, len(backend.Calls))
}

func TestObjMiscHandleRoutesTaggingToTheTaggingHandler(t *testing.T) {
	cases := map[string]struct{ method, operation string }{
		"GET":    {http.MethodGet, "GetObjectTagging"},
		"PUT":    {http.MethodPut, "PutObjectTagging"},
		"DELETE": {http.MethodDelete, "DeleteObjectTagging"},
		"POST":   {http.MethodPost, "ObjectTagging_POST"},
		"HEAD":   {http.MethodHead, "ObjectTagging_HEAD"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			body := strings.NewReader(`<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`)
			rr := ObjMiscdo(h, httptest.NewRequest(tc.method, "/b/k?tagging", body), "b", "k")

			ObjMiscassertNotImplemented(t, rr, tc.operation)
			assert.Equal(t, 0, len(backend.Calls), "?tagging must never reach the backend")
		})
	}
}

// ?acl is checked before ?tagging, so a request carrying both is answered as an
// ACL request. Pinning it makes an accidental reorder visible.
func TestObjMiscHandleACLBeatsTaggingWhenBothArePresent(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?acl&tagging", nil), "b", "k")

	ObjMiscassertNotImplemented(t, rr, "GetObjectACL")
}

// GetObjectAttributes has no route of its own; without the guard in Handle the
// request would fall through to GET and return the object bytes where an XML
// document is expected.
func TestObjMiscHandleRefusesGetObjectAttributesInsteadOfReturningBytes(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			req := httptest.NewRequest(method, "/b/k?attributes&x-amz-object-attributes=ETag", nil)
			rr := ObjMiscdo(h, req, "b", "k")

			ObjMiscassertNotImplemented(t, rr, "GetObjectAttributes")
			assert.Equal(t, 0, len(backend.Calls), "?attributes must never reach the backend")
		})
	}
}

// ---------------------------------------------------------------------------
// The sub-handler accessors the router uses.
// ---------------------------------------------------------------------------

func TestObjMiscSubHandlerAccessorsReturnTheWiredInstances(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	acl := h.GetACLHandler()
	tagging := h.GetTaggingHandler()
	metadata := h.GetMetadataHandler()

	require.NotNil(t, acl)
	require.NotNil(t, tagging)
	require.NotNil(t, metadata)

	// The router calls these once at start-up and keeps the result, so they have
	// to be stable and to carry the same backend the handler was built with.
	assert.Same(t, acl, h.GetACLHandler())
	assert.Same(t, tagging, h.GetTaggingHandler())
	assert.Same(t, metadata, h.GetMetadataHandler())
	assert.Same(t, backend, acl.s3Backend)
	assert.Same(t, backend, tagging.s3Backend)
	assert.Same(t, backend, metadata.s3Backend)

	// And the returned handler is the one that answers.
	rr := ObjMiscdoFunc(acl.Handle, httptest.NewRequest(http.MethodGet, "/b/k?acl", nil),
		map[string]string{"bucket": "b", "key": "k"})
	ObjMiscassertNotImplemented(t, rr, "GetObjectACL")
}

// The ACL and tagging handlers are reached directly by the router, not only
// through Handle, so they are exercised on their own entry point too.
func TestObjMiscACLHandlerDirectEntryPoint(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	for method, operation := range map[string]string{
		http.MethodGet:    "GetObjectACL",
		http.MethodPut:    "PutObjectACL",
		http.MethodDelete: "ObjectACL_DELETE",
	} {
		t.Run(method, func(t *testing.T) {
			rr := ObjMiscdoFunc(h.GetACLHandler().Handle,
				httptest.NewRequest(method, "/b/k?acl", nil),
				map[string]string{"bucket": "b", "key": "deep/key with spaces"})
			ObjMiscassertNotImplemented(t, rr, operation)
		})
	}
	assert.Equal(t, 0, len(backend.Calls))
}

func TestObjMiscTaggingHandlerDirectEntryPoint(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	for method, operation := range map[string]string{
		http.MethodGet:    "GetObjectTagging",
		http.MethodPut:    "PutObjectTagging",
		http.MethodDelete: "DeleteObjectTagging",
		http.MethodPost:   "ObjectTagging_POST",
	} {
		t.Run(method, func(t *testing.T) {
			rr := ObjMiscdoFunc(h.GetTaggingHandler().Handle,
				httptest.NewRequest(method, "/b/k?tagging", nil),
				map[string]string{"bucket": "b", "key": "k"})
			ObjMiscassertNotImplemented(t, rr, operation)
		})
	}
	assert.Equal(t, 0, len(backend.Calls))
}

// ---------------------------------------------------------------------------
// The exported passthrough wrappers the router registers.
// ---------------------------------------------------------------------------

// Legal hold and retention are refused in both directions. The refusal is the
// point: the previous implementation answered 200 for a hold it had not applied
// and for a retention the client never asked for.
func TestObjMiscObjectLockSubResourcesAreRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	vars := map[string]string{"bucket": "b", "key": "k"}

	cases := []struct {
		name      string
		fn        http.HandlerFunc
		method    string
		url       string
		operation string
	}{
		{"legal_hold_get", h.HandleObjectLegalHold, http.MethodGet, "/b/k?legal-hold", "ObjectLegalHold_GET"},
		{"legal_hold_put", h.HandleObjectLegalHold, http.MethodPut, "/b/k?legal-hold", "ObjectLegalHold_PUT"},
		{"retention_get", h.HandleObjectRetention, http.MethodGet, "/b/k?retention", "ObjectRetention_GET"},
		{"retention_put", h.HandleObjectRetention, http.MethodPut, "/b/k?retention", "ObjectRetention_PUT"},
		{"select", h.HandleSelectObjectContent, http.MethodPost, "/b/k?select&select-type=2", "SelectObjectContent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A body that asks for the opposite of what the old code did, to make
			// clear the refusal does not depend on the request document.
			body := strings.NewReader(`<LegalHold><Status>OFF</Status></LegalHold>`)
			rr := ObjMiscdoFunc(tc.fn, httptest.NewRequest(tc.method, tc.url, body), vars)

			ObjMiscassertNotImplemented(t, rr, tc.operation)
			assert.Empty(t, rr.Header().Get("x-amz-object-lock-legal-hold"))
		})
	}
	assert.Equal(t, 0, len(backend.Calls), "a refused sub-resource must not reach the backend")
	backend.AssertNotCalled(t, "PutObjectLegalHold", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "PutObjectRetention", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "SelectObjectContent", mock.Anything, mock.Anything)
}

// DEFECT (major, reported): ?torrent is a pure passthrough. The backend builds
// the torrent from the bytes it holds, which for anything this proxy wrote are
// the ciphertext, so every piece hash in the answer describes ciphertext while
// the client is told 200. A client that downloads through the torrent gets the
// encrypted object and no way to notice.
func TestObjMiscObjectTorrentIsPassedThroughUndecrypted(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	torrent := []byte("d8:announce20:http://tracker/announce4:infod6:lengthi5eee")
	backend.On("GetObjectTorrent", mock.Anything, mock.MatchedBy(func(in *s3.GetObjectTorrentInput) bool {
		return aws.ToString(in.Bucket) == "b" && aws.ToString(in.Key) == "k"
	})).Return(&s3.GetObjectTorrentOutput{Body: io.NopCloser(bytes.NewReader(torrent))}, nil)

	rr := ObjMiscdoFunc(h.HandleObjectTorrent,
		httptest.NewRequest(http.MethodGet, "/b/k?torrent", nil),
		map[string]string{"bucket": "b", "key": "k"})

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/x-bittorrent", rr.Header().Get("Content-Type"))
	assert.Equal(t, torrent, rr.Body.Bytes(),
		"the backend document is forwarded verbatim, ciphertext hashes included")
	backend.AssertExpectations(t)
}

func TestObjMiscObjectTorrentBackendErrorsAreMapped(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"no_such_key":    {&types.NoSuchKey{}, http.StatusNotFound, "NoSuchKey"},
		"no_such_bucket": {&types.NoSuchBucket{}, http.StatusNotFound, "NoSuchBucket"},
		"access_denied": {&smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"},
			http.StatusForbidden, "AccessDenied"},
		"network_error": {errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			http.StatusInternalServerError, "InternalError"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)
			backend.On("GetObjectTorrent", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjMiscdoFunc(h.HandleObjectTorrent,
				httptest.NewRequest(http.MethodGet, "/b/k?torrent", nil),
				map[string]string{"bucket": "b", "key": "k"})

			assert.Equal(t, tc.wantStatus, rr.Code)
			doc := ObjMiscparseError(t, rr.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, "b/k", doc.Resource)
			assert.NotContains(t, rr.Body.String(), "10.0.0.1",
				"the backend endpoint must never reach the client")
			assert.NotEqual(t, "application/x-bittorrent", rr.Header().Get("Content-Type"))
		})
	}
}

// ObjMiscbrokenReader fails partway through, the way a truncated backend
// response does.
type ObjMiscbrokenReader struct {
	prefix []byte
	done   bool
}

func (r *ObjMiscbrokenReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		n := copy(p, r.prefix)
		return n, nil
	}
	return 0, errors.New("backend stream broke")
}

func (r *ObjMiscbrokenReader) Close() error { return nil }

// The status is already committed when the copy starts, so a mid-stream failure
// can only truncate the body. Worth pinning: the client sees 200 and a short
// document, which is why the torrent path cannot report the failure.
func TestObjMiscObjectTorrentStreamFailureTruncatesAfterCommittedStatus(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	backend.On("GetObjectTorrent", mock.Anything, mock.Anything).
		Return(&s3.GetObjectTorrentOutput{Body: &ObjMiscbrokenReader{prefix: []byte("d8:anno")}}, nil)

	rr := ObjMiscdoFunc(h.HandleObjectTorrent,
		httptest.NewRequest(http.MethodGet, "/b/k?torrent", nil),
		map[string]string{"bucket": "b", "key": "k"})

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "d8:anno", rr.Body.String())
}

// The wrappers take bucket and key from the mux vars; an empty key still
// reaches the same refusal rather than a panic.
func TestObjMiscPassthroughWrappersTolerateMissingMuxVars(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	rr := ObjMiscdoFunc(h.HandleObjectLegalHold,
		httptest.NewRequest(http.MethodGet, "/?legal-hold", nil), map[string]string{})
	ObjMiscassertNotImplemented(t, rr, "ObjectLegalHold_GET")

	rr = ObjMiscdoFunc(h.HandleSelectObjectContent,
		httptest.NewRequest(http.MethodPost, "/?select&select-type=2", nil), map[string]string{})
	ObjMiscassertNotImplemented(t, rr, "SelectObjectContent")
}
