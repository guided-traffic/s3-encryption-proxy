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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
// which backend call the request turned into. The routing and the refusals do
// not depend on the storage format; the read verbs do, because an encrypting
// proxy answers GET and HEAD only for an object it wrote itself (ADR 0003), so
// their fixtures come from the write path.
// ---------------------------------------------------------------------------

const ObjMiscaesKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// ObjMiscnewHandler wires a handler with a real AES provider and the default
// metadata prefix.
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
			Providers: []config.EncryptionProvider{{
				Alias:  "test-aes",
				Type:   "aes",
				Config: map[string]interface{}{"aes_key": ObjMiscaesKey},
			}},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 1024
	cfg.Optimizations.MultipartUploadConcurrency = 1

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

// ObjMiscsealed stores one object through a handler of its own and returns what
// the backend was handed: the sealed segment chain and the metadata that makes
// it readable. GET and HEAD serve only an object this proxy wrote, so their
// fixtures have to come from the write path; the separate handler keeps the
// PUT out of the backend mock the test under test asserts on. Every handler
// here wraps the data key with the same configured KEK, so what one stored the
// next one reads.
func ObjMiscsealed(t *testing.T, bucket, key string, plaintext []byte) (stored []byte, metadata map[string]string) {
	t.Helper()
	writer := new(MockS3Backend)
	var in *s3.PutObjectInput
	writer.On("PutObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { in = args.Get(1).(*s3.PutObjectInput) }).
		Return(&s3.PutObjectOutput{ETag: aws.String(`"stored"`)}, nil)

	rr := ObjMiscdo(ObjMiscnewHandler(t, writer),
		httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key, bytes.NewReader(plaintext)), bucket, key)
	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, in)

	body, err := io.ReadAll(in.Body)
	require.NoError(t, err)
	require.Equal(t, aws.ToInt64(in.ContentLength), int64(len(body)),
		"the stored length is declared before the first byte moves")
	return body, in.Metadata
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
		stored, metadata := ObjMiscsealed(t, "b", "k", []byte("plain"))
		backend.On("GetObject", mock.Anything, mock.MatchedBy(func(in *s3.GetObjectInput) bool {
			return aws.ToString(in.Bucket) == "b" && aws.ToString(in.Key) == "k"
		})).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(stored)),
			ContentLength: aws.Int64(int64(len(stored))),
			Metadata:      metadata,
		}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "plain", rr.Body.String())
		// The client is told what it is about to read, not what the backend holds.
		assert.Equal(t, "5", rr.Header().Get("Content-Length"))
		backend.AssertExpectations(t)
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})

	t.Run("HEAD", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		stored, metadata := ObjMiscsealed(t, "b", "k", []byte("plain77"))
		ObjServeStored(backend, stored, s3.GetObjectOutput{
			ETag:     aws.String(`"e"`),
			Metadata: metadata,
		})

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		// The segment framing and the trailer are the proxy's business: HEAD
		// reports the plaintext length the trailer authenticates.
		assert.Equal(t, "7", rr.Header().Get("Content-Length"))
		assert.Greater(t, len(stored), 7, "the stored object is longer than what HEAD reports")
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

// The pass-through these fixtures used to rely on is gone. An object without
// the proxy's metadata is one the proxy did not write, and handing its stored
// bytes to a client that asked for plaintext is exactly what the segmented
// format removed (ADR 0003): both read verbs refuse it, with the same status
// and code, and the body never reaches the client.
func TestObjMiscHandleRefusesAnObjectThisProxyDidNotWrite(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader("plain")),
			ContentLength: aws.Int64(5),
		}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, "InvalidObjectState", ObjMiscparseError(t, rr.Body.Bytes()).Code)
		assert.NotContains(t, rr.Body.String(), "plain", "not one stored byte is served")
	})

	t.Run("HEAD", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		ObjServeStored(backend, []byte("plain"), s3.GetObjectOutput{ETag: aws.String(`"e"`)})

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, "InvalidObjectState", ObjMiscparseError(t, rr.Body.Bytes()).Code)
		// Answering with the stored length would describe an object the client
		// is not allowed to read.
		assert.NotEqual(t, "5", rr.Header().Get("Content-Length"))
	})
}

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

			// The method is wrong, not the operation unimplemented, so the refusal
			// that says what is true is 405 with an Allow header naming the verbs the
			// resource carries (ADR 0007 D8, ADR 0008 D7).
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
			assert.Equal(t, "MethodNotAllowed", ObjMiscparseError(t, rr.Body.Bytes()).Code)
			assert.ElementsMatch(t,
				[]string{"GET", "HEAD", "PUT", "DELETE"},
				ObjMiscallowedMethods(rr),
				"the Allow header names the methods the object resource does carry")
		})
	}
}

// ObjMiscallowedMethods reads the Allow header as the set of verbs it names.
func ObjMiscallowedMethods(rr *httptest.ResponseRecorder) []string {
	header := rr.Header().Get("Allow")
	if header == "" {
		return nil
	}
	methods := strings.Split(header, ",")
	for i, m := range methods {
		methods[i] = strings.TrimSpace(m)
	}
	return methods
}

// Handler.Handle recognises acl, tagging and attributes by name; every other
// object sub-resource is routed by HTTP method in router.go. A sub-resource
// request whose method that route does not carry therefore arrives here, and
// running the base operation for the verb is destructive: DELETE ?legal-hold
// deleted the object and PUT ?restore overwrote it with the restore document.
// That is the same class of bug that made "DELETE /bucket?encryption" delete
// the bucket, and it is now refused the same way.
func TestObjMiscHandleRefusesSubResourcesThatReachTheBaseOperation(t *testing.T) {
	t.Run("DELETE with a sub-resource is refused, not performed", func(t *testing.T) {
		for _, sub := range []string{"legal-hold", "retention", "torrent", "restore", "select", "uploads"} {
			t.Run(sub, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjMiscnewHandler(t, backend)

				rr := ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k?"+sub, nil), "b", "k")

				assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
				assert.Contains(t, rr.Body.String(), "MethodNotAllowed")
				backend.AssertNotCalled(t, "DeleteObject", mock.Anything, mock.Anything)
			})
		}
	})

	// The router requires partNumber to match [0-9]+ and registers the part
	// routes before the catch-all, so a PUT arriving here with both partNumber
	// and uploadId is a part upload whose part number is not a number. It used
	// to run as an ordinary PutObject and the part body replaced the whole
	// object. AWS answers 400 InvalidArgument (ADR 0007). Handle is called
	// directly here, bypassing the router, so the value only has to be present -
	// the router is what proves it is malformed in production.
	t.Run("PUT with a malformed partNumber is answered InvalidArgument", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)

		req := httptest.NewRequest(http.MethodPut, "/b/k?partNumber=abc&uploadId=xyz", strings.NewReader("part body"))
		rr := ObjMiscdo(h, req, "b", "k")

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "InvalidArgument")
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})

	// Only PUT, and only with both parameters. A GET ?partNumber is a real S3
	// read of one part that this proxy does not implement, so NotImplemented is
	// the honest answer there; ADR 0007 scopes the InvalidArgument answer to PUT
	// with both parameters and leaves the half-cases the answer they had.
	t.Run("the InvalidArgument answer is scoped to PUT with both parameters", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			method string
			query  string
		}{
			{"GET with both is a part read", http.MethodGet, "partNumber=1&uploadId=xyz"},
			{"DELETE with both", http.MethodDelete, "partNumber=abc&uploadId=xyz"},
			{"PUT with only a partNumber", http.MethodPut, "partNumber=abc"},
			{"PUT with only an uploadId", http.MethodPut, "uploadId=xyz"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjMiscnewHandler(t, backend)

				rr := ObjMiscdo(h, httptest.NewRequest(tc.method, "/b/k?"+tc.query, nil), "b", "k")

				assert.Equal(t, http.StatusNotImplemented, rr.Code)
				backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
				backend.AssertNotCalled(t, "GetObject", mock.Anything, mock.Anything)
				backend.AssertNotCalled(t, "DeleteObject", mock.Anything, mock.Anything)
			})
		}
	})

	t.Run("PUT ?restore does not store the restore document as the object", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)

		doc := `<RestoreRequest><Days>1</Days></RestoreRequest>`
		req := httptest.NewRequest(http.MethodPut, "/b/k?restore", strings.NewReader(doc))
		rr := ObjMiscdo(h, req, "b", "k")

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		backend.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything)
	})

	// An unknown parameter names a sub-resource the proxy does not implement.
	// Refusing is the only safe answer; performing the base operation is how
	// the bucket-side bug destroyed data.
	t.Run("an unknown sub-resource is refused rather than run as the base operation", func(t *testing.T) {
		for _, sub := range []string{"encryption", "publicAccessBlock", "ownershipControls"} {
			t.Run(sub, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjMiscnewHandler(t, backend)

				rr := ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k?"+sub, nil), "b", "k")

				assert.Equal(t, http.StatusNotImplemented, rr.Code)
				backend.AssertNotCalled(t, "DeleteObject", mock.Anything, mock.Anything)
			})
		}
	})

	// The parameters a base object operation legitimately carries must still
	// reach it, or this guard becomes an outage. X-Amz-Checksum-Mode is the case
	// that proved it: aws-sdk-go-v2 puts it into every pre-signed GetObject URL,
	// the literal allowlist did not have it, and every pre-signed download was
	// answered NotImplemented - which is what the Velero e2e caught as V10.
	t.Run("legitimate base-operation parameters still pass", func(t *testing.T) {
		for _, q := range []string{
			"versionId=v1", "x-id=GetObject", "response-content-type=text%2Fplain",
			"X-Amz-Expires=600", "X-Amz-Checksum-Mode=ENABLED",
			"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Checksum-Mode=ENABLED&X-Amz-Expires=600&x-id=GetObject",
		} {
			t.Run(q, func(t *testing.T) {
				backend := new(MockS3Backend)
				h := ObjMiscnewHandler(t, backend)
				stored, metadata := ObjMiscsealed(t, "b", "k", []byte("plain"))
				backend.On("GetObject", mock.Anything, mock.Anything).
					Return(&s3.GetObjectOutput{
						Body:          io.NopCloser(bytes.NewReader(stored)),
						ContentLength: aws.Int64(int64(len(stored))),
						Metadata:      metadata,
					}, nil)

				rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?"+q, nil), "b", "k")

				assert.Equal(t, http.StatusOK, rr.Code)
				backend.AssertCalled(t, "GetObject", mock.Anything, mock.Anything)
			})
		}
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
	t.Run("the three implemented verbs reach the backend", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("GetObjectTagging", mock.Anything, mock.Anything).
			Return(&s3.GetObjectTaggingOutput{TagSet: []types.Tag{
				{Key: aws.String("a"), Value: aws.String("b")},
			}}, nil)
		backend.On("PutObjectTagging", mock.Anything, mock.Anything).
			Return(&s3.PutObjectTaggingOutput{}, nil)
		backend.On("DeleteObjectTagging", mock.Anything, mock.Anything).
			Return(&s3.DeleteObjectTaggingOutput{}, nil)

		body := func() *strings.Reader {
			return strings.NewReader(`<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`)
		}

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?tagging", nil), "b", "k")
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "<Tagging>")
		assert.Contains(t, rr.Body.String(), "<Key>a</Key>")

		rr = ObjMiscdo(h, httptest.NewRequest(http.MethodPut, "/b/k?tagging", body()), "b", "k")
		assert.Equal(t, http.StatusOK, rr.Code)

		rr = ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k?tagging", nil), "b", "k")
		assert.Equal(t, http.StatusNoContent, rr.Code)

		backend.AssertExpectations(t)
	})

	// A verb S3 does not define on this sub-resource still says so rather than
	// running the base operation for it.
	for name, operation := range map[string]string{
		http.MethodPost: "ObjectTagging_POST",
		http.MethodHead: "ObjectTagging_HEAD",
	} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			rr := ObjMiscdo(h, httptest.NewRequest(name, "/b/k?tagging", nil), "b", "k")

			ObjMiscassertNotImplemented(t, rr, operation)
			assert.Equal(t, 0, len(backend.Calls))
		})
	}
}

// The three passthrough sub-resources answer an S3 document, not the SDK's
// output struct marshalled by field name (ADR 0007 D4, ADR 0008).
func TestObjMiscRetentionAndLegalHoldArePassthrough(t *testing.T) {
	retainUntil := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("retention round trip", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("GetObjectRetention", mock.Anything, mock.Anything).
			Return(&s3.GetObjectRetentionOutput{Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: aws.Time(retainUntil),
			}}, nil)
		var put *s3.PutObjectRetentionInput
		backend.On("PutObjectRetention", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { put = args.Get(1).(*s3.PutObjectRetentionInput) }).
			Return(&s3.PutObjectRetentionOutput{}, nil)

		vars := map[string]string{"bucket": "b", "key": "k"}
		rr := ObjMiscdoFunc(h.HandleObjectRetention,
			httptest.NewRequest(http.MethodGet, "/b/k?retention", nil), vars)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "<Retention>")
		assert.Contains(t, rr.Body.String(), "<Mode>GOVERNANCE</Mode>")
		assert.Contains(t, rr.Body.String(), "<RetainUntilDate>2099-01-02T03:04:05.000Z</RetainUntilDate>")

		body := strings.NewReader(
			`<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-02T03:04:05Z</RetainUntilDate></Retention>`)
		req := httptest.NewRequest(http.MethodPut, "/b/k?retention", body)
		req.Header.Set("x-amz-bypass-governance-retention", "true")
		rr = ObjMiscdoFunc(h.HandleObjectRetention, req, vars)

		require.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, put)
		assert.Equal(t, types.ObjectLockRetentionModeCompliance, put.Retention.Mode,
			"the mode the client sent, not a fabricated GOVERNANCE")
		assert.Equal(t, retainUntil, aws.ToTime(put.Retention.RetainUntilDate))
		assert.True(t, aws.ToBool(put.BypassGovernanceRetention))
	})

	t.Run("legal hold round trip", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		backend.On("GetObjectLegalHold", mock.Anything, mock.Anything).
			Return(&s3.GetObjectLegalHoldOutput{LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			}}, nil)
		var put *s3.PutObjectLegalHoldInput
		backend.On("PutObjectLegalHold", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { put = args.Get(1).(*s3.PutObjectLegalHoldInput) }).
			Return(&s3.PutObjectLegalHoldOutput{}, nil)

		vars := map[string]string{"bucket": "b", "key": "k"}
		rr := ObjMiscdoFunc(h.HandleObjectLegalHold,
			httptest.NewRequest(http.MethodGet, "/b/k?legal-hold", nil), vars)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "<LegalHold>")
		assert.Contains(t, rr.Body.String(), "<Status>ON</Status>")

		// The release is the case the old handler got wrong: it read the body,
		// discarded it and always sent Status=On.
		body := strings.NewReader(`<LegalHold><Status>OFF</Status></LegalHold>`)
		rr = ObjMiscdoFunc(h.HandleObjectLegalHold,
			httptest.NewRequest(http.MethodPut, "/b/k?legal-hold", body), vars)

		require.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, put)
		assert.Equal(t, types.ObjectLockLegalHoldStatusOff, put.LegalHold.Status,
			"a request to release a hold must not apply one")
	})

	t.Run("a body that does not parse is MalformedXML", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)

		vars := map[string]string{"bucket": "b", "key": "k"}
		for subResource, fn := range map[string]http.HandlerFunc{
			"retention":  h.HandleObjectRetention,
			"legal-hold": h.HandleObjectLegalHold,
			"tagging":    h.GetTaggingHandler().Handle,
		} {
			rr := ObjMiscdoFunc(fn, httptest.NewRequest(http.MethodPut, "/b/k?"+subResource,
				strings.NewReader("<not-xml")), vars)
			assert.Equal(t, http.StatusBadRequest, rr.Code, subResource)
			assert.Contains(t, rr.Body.String(), "MalformedXML", subResource)
		}
		assert.Equal(t, 0, len(backend.Calls), "a malformed document never reaches the backend")
	})
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

	require.NotNil(t, acl)
	require.NotNil(t, tagging)

	// The router calls these once at start-up and keeps the result, so they have
	// to be stable and to carry the same backend the handler was built with.
	assert.Same(t, acl, h.GetACLHandler())
	assert.Same(t, tagging, h.GetTaggingHandler())
	assert.Same(t, backend, acl.s3Backend)
	assert.Same(t, backend, tagging.s3Backend)

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

	rr := ObjMiscdoFunc(h.GetTaggingHandler().Handle,
		httptest.NewRequest(http.MethodPost, "/b/k?tagging", nil),
		map[string]string{"bucket": "b", "key": "k"})

	ObjMiscassertNotImplemented(t, rr, "ObjectTagging_POST")
	assert.Equal(t, 0, len(backend.Calls))
}

// ---------------------------------------------------------------------------
// The exported passthrough wrappers the router registers.
// ---------------------------------------------------------------------------

// S3 Select stays refused: it runs a query over the object, which is content
// the backend holds as ciphertext. Retention and legal hold went the other way
// and are passthrough now (ADR 0007 D4); a verb neither of them defines still
// says NotImplemented rather than running something else.
func TestObjMiscObjectSubResourcesRefusedOnUnsupportedVerbs(t *testing.T) {
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
		{"legal_hold_delete", h.HandleObjectLegalHold, http.MethodDelete, "/b/k?legal-hold", "ObjectLegalHold_DELETE"},
		{"retention_delete", h.HandleObjectRetention, http.MethodDelete, "/b/k?retention", "ObjectRetention_DELETE"},
		{"select", h.HandleSelectObjectContent, http.MethodPost, "/b/k?select&select-type=2", "SelectObjectContent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(`<LegalHold><Status>OFF</Status></LegalHold>`)
			rr := ObjMiscdoFunc(tc.fn, httptest.NewRequest(tc.method, tc.url, body), vars)

			ObjMiscassertNotImplemented(t, rr, tc.operation)
			assert.Empty(t, rr.Header().Get("x-amz-object-lock-legal-hold"))
		})
	}
	assert.Equal(t, 0, len(backend.Calls), "a refused verb must not reach the backend")
	backend.AssertNotCalled(t, "PutObjectLegalHold", mock.Anything, mock.Anything)
	backend.AssertNotCalled(t, "PutObjectRetention", mock.Anything, mock.Anything)
}

// ?torrent is refused under an encrypting provider: the backend composes the
// document from the bytes it holds, which are the ciphertext, and a response
// carries only what the proxy can vouch for (ADR 0008 D1/D11, ADR 0007 D1).
func TestObjMiscObjectTorrentIsRefusedNotPassedThroughUndecrypted(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	// Stubbed so a handler that still calls it fails on the assertions below
	// rather than on an unexpected call.
	torrent := []byte("d8:announce20:http://tracker/announce4:infod6:lengthi5eee")
	backend.On("GetObjectTorrent", mock.Anything, mock.Anything).
		Return(&s3.GetObjectTorrentOutput{Body: io.NopCloser(bytes.NewReader(torrent))}, nil)

	rr := ObjMiscdoFunc(h.HandleObjectTorrent,
		httptest.NewRequest(http.MethodGet, "/b/k?torrent", nil),
		map[string]string{"bucket": "b", "key": "k"})

	// Encryption forecloses the operation, so the request never reaches the
	// backend and not one byte of its document reaches the client (ADR 0007 D1).
	backend.AssertNotCalled(t, "GetObjectTorrent", mock.Anything, mock.Anything)
	assert.NotEqual(t, "application/x-bittorrent", rr.Header().Get("Content-Type"))
	assert.NotContains(t, rr.Body.String(), "announce")
	// Open decision: 422 NotSupportedWithEncryption or 501 NotImplemented naming
	// ObjectTorrent is the owner's call (ADR 0007 D8); asserted is the first.
	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
	assert.Equal(t, "NotSupportedWithEncryption", ObjMiscparseError(t, rr.Body.Bytes()).Code)
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

// The wrappers take bucket and key from the mux vars; an empty key still
// reaches the same refusal rather than a panic.
func TestObjMiscPassthroughWrappersTolerateMissingMuxVars(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	rr := ObjMiscdoFunc(h.HandleObjectLegalHold,
		httptest.NewRequest(http.MethodDelete, "/?legal-hold", nil), map[string]string{})
	ObjMiscassertNotImplemented(t, rr, "ObjectLegalHold_DELETE")

	rr = ObjMiscdoFunc(h.HandleSelectObjectContent,
		httptest.NewRequest(http.MethodPost, "/?select&select-type=2", nil), map[string]string{})
	ObjMiscassertNotImplemented(t, rr, "SelectObjectContent")
}
