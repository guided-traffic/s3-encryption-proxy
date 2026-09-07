package bucket

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
)

const bktBucket = "test-bucket"

// BktapiError builds a typed backend error with the given S3 code, the shape a
// real backend failure arrives in.
func BktapiError(code, message string) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "BktOperation",
		Err:           &smithy.GenericAPIError{Code: code, Message: message},
	}
}

// BktfailingReader is a request body that fails mid-read, the shape a client
// that disconnects during an upload produces.
type BktfailingReader struct{}

func (BktfailingReader) Read([]byte) (int, error) { return 0, errors.New("client went away") }
func (BktfailingReader) Close() error             { return nil }

// BktnewHandlerWith builds a bucket Handler over the given backend, with the
// logger silenced so a table of error-path cases does not flood the output.
func BktnewHandlerWith(backend interfaces.S3BackendInterface) *Handler {
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	return NewHandler(backend, logger, "s3ep-", &config.Config{})
}

// Bktrequest builds a request with the mux bucket variable already set, the way
// the router hands it to a handler.
func Bktrequest(method, url string, body []byte) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, url, nil)
	} else {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
	}
	return mux.SetURLVars(req, map[string]string{"bucket": bktBucket})
}

// Bktserve runs one request against a sub-resource handler and returns the
// recorder.
func Bktserve(h http.HandlerFunc, method, url string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, Bktrequest(method, url, body))
	return w
}

// TestBktSubResourceGetForwardsBackendErrorsUnchanged walks every bucket
// sub-resource GET and asserts that a backend error reaches the client as the
// S3 code the backend used, with the matching HTTP status - not as a 500 and
// not as a 200 with an empty document.
func TestBktSubResourceGetForwardsBackendErrorsUnchanged(t *testing.T) {
	type target struct {
		name string
		call string
		run  func(h *Handler) http.HandlerFunc
	}
	targets := []target{
		{"acl", "GetBucketAcl", func(h *Handler) http.HandlerFunc { return h.GetACLHandler().Handle }},
		{"cors", "GetBucketCors", func(h *Handler) http.HandlerFunc { return h.GetCORSHandler().Handle }},
		{"policy", "GetBucketPolicy", func(h *Handler) http.HandlerFunc { return h.GetPolicyHandler().Handle }},
		{"location", "GetBucketLocation", func(h *Handler) http.HandlerFunc { return h.GetLocationHandler().Handle }},
		{"logging", "GetBucketLogging", func(h *Handler) http.HandlerFunc { return h.GetLoggingHandler().Handle }},
		{"versioning", "GetBucketVersioning", func(h *Handler) http.HandlerFunc { return h.GetVersioningHandler().Handle }},
		{"tagging", "GetBucketTagging", func(h *Handler) http.HandlerFunc { return h.GetTaggingHandler().Handle }},
		{"notification", "GetBucketNotificationConfiguration", func(h *Handler) http.HandlerFunc {
			return h.GetNotificationHandler().Handle
		}},
		{"lifecycle", "GetBucketLifecycleConfiguration", func(h *Handler) http.HandlerFunc {
			return h.GetLifecycleHandler().Handle
		}},
		{"replication", "GetBucketReplication", func(h *Handler) http.HandlerFunc { return h.GetReplicationHandler().Handle }},
		{"website", "GetBucketWebsite", func(h *Handler) http.HandlerFunc { return h.GetWebsiteHandler().Handle }},
		{"accelerate", "GetBucketAccelerateConfiguration", func(h *Handler) http.HandlerFunc {
			return h.GetAccelerateHandler().Handle
		}},
		{"requestPayment", "GetBucketRequestPayment", func(h *Handler) http.HandlerFunc {
			return h.GetRequestPaymentHandler().Handle
		}},
	}

	errorCases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"NoSuchBucket", BktapiError("NoSuchBucket", "The specified bucket does not exist"), http.StatusNotFound, "NoSuchBucket"},
		{"AccessDenied", BktapiError("AccessDenied", "Access Denied"), http.StatusForbidden, "AccessDenied"},
		{"SlowDown", BktapiError("SlowDown", "Please reduce your request rate"), http.StatusServiceUnavailable, "SlowDown"},
		{"network_error", errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			http.StatusInternalServerError, "InternalError"},
	}

	for _, tg := range targets {
		for _, ec := range errorCases {
			t.Run(tg.name+"_"+ec.name, func(t *testing.T) {
				backend := &MockS3Backend{}
				backend.On(tg.call, mock.Anything, mock.Anything).Return(nil, ec.err)
				h := BktnewHandlerWith(backend)

				w := Bktserve(tg.run(h), http.MethodGet, "/"+bktBucket+"?"+tg.name, nil)

				assert.Equal(t, ec.wantStatus, w.Code)
				doc := BktparseError(t, w.Body.Bytes())
				assert.Equal(t, ec.wantCode, doc.Code)
				assert.Equal(t, bktBucket, doc.Resource, "the resource names the bucket, never a key")
				// A transport failure must not leak the backend endpoint.
				assert.NotContains(t, w.Body.String(), "10.0.0.1")
				backend.AssertExpectations(t)
			})
		}
	}
}

// TestBktACLGetReturnsTheBackendDocument covers handleGetACL and records the
// wire shape a client actually receives.
func TestBktACLGetReturnsTheBackendDocument(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketAcl", mock.Anything, mock.MatchedBy(func(in *s3.GetBucketAclInput) bool {
		return aws.ToString(in.Bucket) == bktBucket
	})).Return(&s3.GetBucketAclOutput{
		Owner: &s3types.Owner{ID: aws.String("owner-1"), DisplayName: aws.String("owner")},
		Grants: []s3types.Grant{{
			Grantee:    &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: aws.String("owner-1")},
			Permission: s3types.PermissionFullControl,
		}},
	}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetACLHandler().Handle, http.MethodGet, "/"+bktBucket+"?acl", nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, "<ID>owner-1</ID>")
	assert.Contains(t, body, "<Permission>FULL_CONTROL</Permission>")
	// Deviation from S3, pinned deliberately: the response is the aws-sdk-go-v2
	// output struct XML-encoded, so the root element is <GetBucketAclOutput>
	// rather than <AccessControlPolicy>, there is no S3 namespace, no XML
	// prolog, and an internal <ResultMetadata> element leaks into the document.
	assert.True(t, strings.HasPrefix(body, "<GetBucketAclOutput>"),
		"root element is the SDK struct name, not AccessControlPolicy: %s", body)
	assert.NotContains(t, body, "<?xml")
	assert.NotContains(t, body, "xmlns")
	assert.Contains(t, body, "<ResultMetadata>")
	backend.AssertExpectations(t)
}

// TestBktACLPutCannedHeaderIsForwarded pins that x-amz-acl short-circuits the
// body parse and reaches the backend verbatim.
func TestBktACLPutCannedHeaderIsForwarded(t *testing.T) {
	for _, canned := range []string{"private", "public-read", "public-read-write", "authenticated-read", "not-a-real-acl"} {
		t.Run(canned, func(t *testing.T) {
			backend := &MockS3Backend{}
			backend.On("PutBucketAcl", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketAclInput) bool {
				return string(in.ACL) == canned && in.AccessControlPolicy == nil
			})).Return(&s3.PutBucketAclOutput{}, nil)
			h := BktnewHandlerWith(backend)

			req := Bktrequest(http.MethodPut, "/"+bktBucket+"?acl", []byte("<AccessControlPolicy/>"))
			req.Header.Set("x-amz-acl", canned)
			w := httptest.NewRecorder()
			h.GetACLHandler().Handle(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Empty(t, w.Body.String(), "PUT ?acl answers with an empty body")
			backend.AssertExpectations(t)
		})
	}
}

// TestBktACLPutParsesTheBodyWhenNoCannedHeader covers the body branch of
// handlePutACL, including the malformed-XML refusal.
func TestBktACLPutParsesTheBodyWhenNoCannedHeader(t *testing.T) {
	// DEFECT, pinned deliberately: the body is unmarshalled into the
	// aws-sdk-go-v2 type types.AccessControlPolicy, which carries no xml struct
	// tags. <Owner> happens to match the Go field name and survives;
	// <AccessControlList><Grant> does not match the field Grants, so every grant
	// the client sent is dropped and the proxy still answers 200. The client is
	// told its ACL was applied while the backend receives an ACL with no grants.
	t.Run("grants_in_the_body_are_silently_dropped", func(t *testing.T) {
		body := []byte(`<AccessControlPolicy>
  <Owner><ID>owner-1</ID></Owner>
  <AccessControlList>
    <Grant><Grantee><ID>reader</ID></Grantee><Permission>READ</Permission></Grant>
    <Grant><Grantee><ID>writer</ID></Grantee><Permission>WRITE</Permission></Grant>
  </AccessControlList>
</AccessControlPolicy>`)
		backend := &MockS3Backend{}
		var forwarded *s3.PutBucketAclInput
		backend.On("PutBucketAcl", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			forwarded = args.Get(1).(*s3.PutBucketAclInput)
		}).Return(&s3.PutBucketAclOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", body)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, forwarded)
		require.NotNil(t, forwarded.AccessControlPolicy)
		assert.Equal(t, "owner-1", aws.ToString(forwarded.AccessControlPolicy.Owner.ID),
			"the owner survives because <Owner> matches the Go field name")
		assert.Empty(t, forwarded.AccessControlPolicy.Grants,
			"every <Grant> the client sent was dropped, and the client was told 200")
		backend.AssertExpectations(t)
	})

	// A body that is not an ACL document at all is accepted the same way:
	// encoding/xml does not check the root element, so there is no validation
	// between "well-formed XML" and "forwarded to the backend".
	t.Run("a_body_that_is_not_an_acl_is_accepted", func(t *testing.T) {
		backend := &MockS3Backend{}
		var forwarded *s3.PutBucketAclInput
		backend.On("PutBucketAcl", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			forwarded = args.Get(1).(*s3.PutBucketAclInput)
		}).Return(&s3.PutBucketAclOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl",
			[]byte(`<CompletelyUnrelated><Hello>world</Hello></CompletelyUnrelated>`))

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, forwarded)
		require.NotNil(t, forwarded.AccessControlPolicy)
		assert.Nil(t, forwarded.AccessControlPolicy.Owner)
		assert.Empty(t, forwarded.AccessControlPolicy.Grants)
	})

	t.Run("malformed_xml_is_refused_as_plain_text", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", []byte("<AccessControlPolicy>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		// Deviation from S3, pinned deliberately: the refusal is a plain-text
		// body, not an S3 <Error> document, so a client cannot read a <Code>.
		assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
		assert.Equal(t, "Invalid ACL XML format\n", w.Body.String())
		backend.AssertNotCalled(t, "PutBucketAcl", mock.Anything, mock.Anything)
	})

	t.Run("empty_body_is_forwarded_with_no_acl_at_all", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketAcl", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketAclInput) bool {
			return in.AccessControlPolicy == nil && in.ACL == ""
		})).Return(&s3.PutBucketAclOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", nil)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("unreadable_body_is_an_s3_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket+"?acl", nil)
		req.Body = BktfailingReader{}
		req.ContentLength = 64
		w := httptest.NewRecorder()
		h.GetACLHandler().Handle(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		doc := BktparseError(t, w.Body.Bytes())
		assert.Equal(t, "InternalError", doc.Code)
		assert.NotContains(t, w.Body.String(), "client went away")
		backend.AssertNotCalled(t, "PutBucketAcl", mock.Anything, mock.Anything)
	})

	t.Run("backend_error_is_forwarded", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketAcl", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "AccessDenied", BktparseError(t, w.Body.Bytes()).Code)
	})
}

// TestBktACLWithoutBackendFabricatesAnAnswer covers the nil-backend fallback in
// acl.go. Production always wires a backend, so this path is scaffolding - but
// it is scaffolding that answers "this bucket grants FULL_CONTROL" with no
// backend behind it, which is why it is pinned rather than assumed harmless.
func TestBktACLWithoutBackendFabricatesAnAnswer(t *testing.T) {
	h := BktnewHandlerWith(nil)

	t.Run("GET", func(t *testing.T) {
		w := Bktserve(h.GetACLHandler().Handle, http.MethodGet, "/"+bktBucket+"?acl", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<Permission>FULL_CONTROL</Permission>")
		assert.Contains(t, w.Body.String(), "mock-owner-id")
	})

	t.Run("PUT", func(t *testing.T) {
		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", []byte("<AccessControlPolicy/>"))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
	})

	t.Run("DELETE", func(t *testing.T) {
		w := Bktserve(h.GetACLHandler().Handle, http.MethodDelete, "/"+bktBucket+"?acl", nil)
		assert.Equal(t, http.StatusNotImplemented, w.Code)
		assert.Equal(t, "BucketACL_DELETE", BktparseError(t, w.Body.Bytes()).Resource)
	})
}

// TestBktCORSWithoutBackendFabricatesAWideOpenPolicy is the same scaffolding in
// cors.go, and the fabricated answer is a policy that allows every origin and
// every method.
func TestBktCORSWithoutBackendFabricatesAWideOpenPolicy(t *testing.T) {
	h := BktnewHandlerWith(nil)

	t.Run("GET", func(t *testing.T) {
		w := Bktserve(h.GetCORSHandler().Handle, http.MethodGet, "/"+bktBucket+"?cors", nil)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<AllowedOrigin>*</AllowedOrigin>")
		assert.Contains(t, w.Body.String(), "<AllowedHeader>*</AllowedHeader>")
	})

	t.Run("PUT", func(t *testing.T) {
		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DELETE", func(t *testing.T) {
		w := Bktserve(h.GetCORSHandler().Handle, http.MethodDelete, "/"+bktBucket+"?cors", nil)
		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
	})

	t.Run("POST", func(t *testing.T) {
		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPost, "/"+bktBucket+"?cors", nil)
		assert.Equal(t, http.StatusNotImplemented, w.Code)
		assert.Equal(t, "BucketCORS_POST", BktparseError(t, w.Body.Bytes()).Resource)
	})
}

// TestBktCORSRoundTrip covers handleGetCORS, handlePutCORS and handleDeleteCORS
// over a real backend.
func TestBktCORSRoundTrip(t *testing.T) {
	t.Run("GET_returns_the_rules", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("GetBucketCors", mock.Anything, mock.Anything).Return(&s3.GetBucketCorsOutput{
			CORSRules: []s3types.CORSRule{{
				AllowedOrigins: []string{"https://example.test"},
				AllowedMethods: []string{"GET"},
				MaxAgeSeconds:  aws.Int32(120),
			}},
		}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodGet, "/"+bktBucket+"?cors", nil)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<AllowedOrigins>https://example.test</AllowedOrigins>")
		assert.Contains(t, w.Body.String(), "<MaxAgeSeconds>120</MaxAgeSeconds>")
		// Deviation: S3 names the elements <AllowedOrigin>/<AllowedMethod> inside
		// <CORSConfiguration>; the SDK struct field names are plural.
		assert.True(t, strings.HasPrefix(w.Body.String(), "<GetBucketCorsOutput>"))
	})

	// DEFECT, pinned deliberately: a real S3 CORSConfiguration document is
	// unmarshalled into aws-sdk-go-v2 types.CORSConfiguration, which has no xml
	// struct tags. S3 names the elements <CORSRule>, <AllowedOrigin>,
	// <AllowedMethod>; the Go fields are CORSRules, AllowedOrigins,
	// AllowedMethods, so nothing matches. The proxy forwards a CORS
	// configuration with zero rules and answers 200: the rules a client sent
	// never reach the backend, and the client is told the call succeeded.
	t.Run("a_real_cors_document_loses_every_rule", func(t *testing.T) {
		body := []byte(`<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>https://a.test</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <MaxAgeSeconds>3000</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>`)
		backend := &MockS3Backend{}
		var forwarded *s3.PutBucketCorsInput
		backend.On("PutBucketCors", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			forwarded = args.Get(1).(*s3.PutBucketCorsInput)
		}).Return(&s3.PutBucketCorsOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", body)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
		require.NotNil(t, forwarded)
		require.NotNil(t, forwarded.CORSConfiguration)
		assert.Empty(t, forwarded.CORSConfiguration.CORSRules,
			"the client rules were dropped, and the client was told 200")
		backend.AssertExpectations(t)
	})

	// The same parse does accept a document written with the Go field names,
	// which no S3 client emits. Kept as the counter-example that identifies the
	// cause: the parser expects Go field names, not S3 element names.
	t.Run("only_go_field_names_parse", func(t *testing.T) {
		body := []byte(`<CORSConfiguration>
  <CORSRules>
    <AllowedOrigins>https://a.test</AllowedOrigins>
    <AllowedMethods>GET</AllowedMethods>
    <MaxAgeSeconds>3000</MaxAgeSeconds>
  </CORSRules>
</CORSConfiguration>`)
		backend := &MockS3Backend{}
		backend.On("PutBucketCors", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketCorsInput) bool {
			return in.CORSConfiguration != nil && len(in.CORSConfiguration.CORSRules) == 1 &&
				in.CORSConfiguration.CORSRules[0].AllowedOrigins[0] == "https://a.test" &&
				aws.ToInt32(in.CORSConfiguration.CORSRules[0].MaxAgeSeconds) == 3000
		})).Return(&s3.PutBucketCorsOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", body)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("PUT_with_empty_body_is_refused_as_plain_text", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
		assert.Equal(t, "Missing CORS configuration\n", w.Body.String())
		backend.AssertNotCalled(t, "PutBucketCors", mock.Anything, mock.Anything)
	})

	t.Run("PUT_with_malformed_xml_is_refused_as_plain_text", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", []byte("<CORSConfiguration>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "Invalid CORS XML format\n", w.Body.String())
		backend.AssertNotCalled(t, "PutBucketCors", mock.Anything, mock.Anything)
	})

	t.Run("PUT_unreadable_body", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket+"?cors", nil)
		req.Body = BktfailingReader{}
		req.ContentLength = 32
		w := httptest.NewRecorder()
		h.GetCORSHandler().Handle(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "InternalError", BktparseError(t, w.Body.Bytes()).Code)
	})

	t.Run("PUT_backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketCors", mock.Anything, mock.Anything).
			Return(nil, BktapiError("MalformedXML", "bad rule"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors",
			[]byte("<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
	})

	t.Run("DELETE_answers_204_with_no_body", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketCors", mock.Anything, mock.MatchedBy(func(in *s3.DeleteBucketCorsInput) bool {
			return aws.ToString(in.Bucket) == bktBucket
		})).Return(&s3.DeleteBucketCorsOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodDelete, "/"+bktBucket+"?cors", nil)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
		backend.AssertExpectations(t)
	})

	t.Run("DELETE_backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketCors", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchCORSConfiguration", "not configured"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodDelete, "/"+bktBucket+"?cors", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchCORSConfiguration", BktparseError(t, w.Body.Bytes()).Code)
	})
}

// TestBktLoggingGetTranslatesEveryGranteeAndPermission covers the conversion
// arms of handleGetLogging, which turn the SDK enum values into the strings the
// S3 BucketLoggingStatus document uses.
func TestBktLoggingGetTranslatesEveryGranteeAndPermission(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketLogging", mock.Anything, mock.Anything).Return(&s3.GetBucketLoggingOutput{
		LoggingEnabled: &s3types.LoggingEnabled{
			TargetBucket: aws.String("logs"),
			TargetPrefix: aws.String("access/"),
			TargetGrants: []s3types.TargetGrant{
				{
					Permission: s3types.BucketLogsPermissionFullControl,
					Grantee:    &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: aws.String("u1"), DisplayName: aws.String("User One")},
				},
				{
					Permission: s3types.BucketLogsPermissionRead,
					Grantee:    &s3types.Grantee{Type: s3types.TypeAmazonCustomerByEmail, EmailAddress: aws.String("a@b.test")},
				},
				{
					Permission: s3types.BucketLogsPermissionWrite,
					Grantee:    &s3types.Grantee{Type: s3types.TypeGroup, URI: aws.String("http://acs.amazonaws.com/groups/s3/LogDelivery")},
				},
				// An unknown permission and a nil grantee: both arms fall through
				// silently today, so the grant reaches the client empty.
				{Permission: s3types.BucketLogsPermission("SOMETHING_ELSE")},
			},
		},
	}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLoggingHandler().Handle, http.MethodGet, "/"+bktBucket+"?logging", nil)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.HasPrefix(body, "<BucketLoggingStatus>"), "logging is one of the few real S3 documents: %s", body)
	assert.Contains(t, body, "<TargetBucket>logs</TargetBucket>")
	assert.Contains(t, body, "<TargetPrefix>access/</TargetPrefix>")
	assert.Contains(t, body, `<Grantee type="CanonicalUser">`)
	assert.Contains(t, body, "<DisplayName>User One</DisplayName>")
	assert.Contains(t, body, `<Grantee type="AmazonCustomerByEmail">`)
	assert.Contains(t, body, "<EmailAddress>a@b.test</EmailAddress>")
	assert.Contains(t, body, `<Grantee type="Group">`)
	assert.Contains(t, body, "<URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>")
	assert.Contains(t, body, "<Permission>FULL_CONTROL</Permission>")
	assert.Contains(t, body, "<Permission>READ</Permission>")
	assert.Contains(t, body, "<Permission>WRITE</Permission>")
	assert.NotContains(t, body, "SOMETHING_ELSE", "an unknown permission is dropped, not passed through")
}

// TestBktLoggingGetDisabledIsAnEmptyStatus pins the "logging is off" document.
func TestBktLoggingGetDisabledIsAnEmptyStatus(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketLogging", mock.Anything, mock.Anything).Return(&s3.GetBucketLoggingOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLoggingHandler().Handle, http.MethodGet, "/"+bktBucket+"?logging", nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<BucketLoggingStatus></BucketLoggingStatus>", w.Body.String())
}

// TestBktLoggingPutRoundTrip covers handlePutLogging including every grantee
// and permission arm of the reverse conversion.
func TestBktLoggingPutRoundTrip(t *testing.T) {
	t.Run("full_configuration_is_forwarded", func(t *testing.T) {
		body := []byte(`<BucketLoggingStatus>
  <LoggingEnabled>
    <TargetBucket>logs</TargetBucket>
    <TargetPrefix>access/</TargetPrefix>
    <TargetGrants>
      <Grant><Grantee type="CanonicalUser"><ID>u1</ID><DisplayName>User One</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>
      <Grant><Grantee type="AmazonCustomerByEmail"><EmailAddress>a@b.test</EmailAddress></Grantee><Permission>READ</Permission></Grant>
      <Grant><Grantee type="Group"><URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI></Grantee><Permission>WRITE</Permission></Grant>
      <Grant><Grantee type="Martian"><ID>x</ID></Grantee><Permission>TELEPORT</Permission></Grant>
    </TargetGrants>
  </LoggingEnabled>
</BucketLoggingStatus>`)
		backend := &MockS3Backend{}
		backend.On("PutBucketLogging", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketLoggingInput) bool {
			if in.BucketLoggingStatus == nil || in.BucketLoggingStatus.LoggingEnabled == nil {
				return false
			}
			le := in.BucketLoggingStatus.LoggingEnabled
			if aws.ToString(le.TargetBucket) != "logs" || aws.ToString(le.TargetPrefix) != "access/" {
				return false
			}
			if len(le.TargetGrants) != 4 {
				return false
			}
			return le.TargetGrants[0].Permission == s3types.BucketLogsPermissionFullControl &&
				le.TargetGrants[1].Grantee.Type == s3types.TypeAmazonCustomerByEmail &&
				le.TargetGrants[2].Grantee.Type == s3types.TypeGroup &&
				// The unknown grantee type and permission are dropped to the zero
				// value rather than refused.
				le.TargetGrants[3].Permission == "" && le.TargetGrants[3].Grantee.Type == ""
		})).Return(&s3.PutBucketLoggingOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPut, "/"+bktBucket+"?logging", body)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("status_without_LoggingEnabled_disables_logging", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketLogging", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketLoggingInput) bool {
			return in.BucketLoggingStatus != nil && in.BucketLoggingStatus.LoggingEnabled == nil
		})).Return(&s3.PutBucketLoggingOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPut, "/"+bktBucket+"?logging",
			[]byte("<BucketLoggingStatus></BucketLoggingStatus>"))

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("empty_body_is_MalformedXML", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPut, "/"+bktBucket+"?logging", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		doc := BktparseError(t, w.Body.Bytes())
		assert.Equal(t, "MalformedXML", doc.Code)
		backend.AssertNotCalled(t, "PutBucketLogging", mock.Anything, mock.Anything)
	})

	t.Run("malformed_body_is_MalformedXML", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPut, "/"+bktBucket+"?logging",
			[]byte("<BucketLoggingStatus>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
	})

	t.Run("unreadable_body", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket+"?logging", nil)
		req.Body = BktfailingReader{}
		req.ContentLength = 16
		w := httptest.NewRecorder()
		h.GetLoggingHandler().Handle(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketLogging", mock.Anything, mock.Anything).
			Return(nil, BktapiError("InvalidArgument", "target bucket is not owned by you"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPut, "/"+bktBucket+"?logging",
			[]byte("<BucketLoggingStatus><LoggingEnabled><TargetBucket>x</TargetBucket></LoggingEnabled></BucketLoggingStatus>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "InvalidArgument", BktparseError(t, w.Body.Bytes()).Code)
	})
}

// TestBktLoggingDeleteIsUnreachableThroughTheRouter covers handleDeleteLogging.
// router.go registers ?logging for GET and PUT only, so this arm can only be
// reached by calling the handler directly - the matrix test pins that a real
// DELETE /bucket?logging is answered 405.
func TestBktLoggingDeleteIsUnreachableThroughTheRouter(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("PutBucketLogging", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketLoggingInput) bool {
		return in.BucketLoggingStatus != nil && in.BucketLoggingStatus.LoggingEnabled == nil
	})).Return(&s3.PutBucketLoggingOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLoggingHandler().Handle, http.MethodDelete, "/"+bktBucket+"?logging", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<BucketLoggingStatus></BucketLoggingStatus>", w.Body.String())
	backend.AssertExpectations(t)

	t.Run("unsupported_method", func(t *testing.T) {
		w := Bktserve(h.GetLoggingHandler().Handle, http.MethodPatch, "/"+bktBucket+"?logging", nil)
		assert.Equal(t, http.StatusNotImplemented, w.Code)
		assert.Equal(t, "BucketLogging_PATCH", BktparseError(t, w.Body.Bytes()).Resource)
	})

	t.Run("delete_backend_error", func(t *testing.T) {
		failing := &MockS3Backend{}
		failing.On("PutBucketLogging", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		fh := BktnewHandlerWith(failing)

		w := Bktserve(fh.GetLoggingHandler().Handle, http.MethodDelete, "/"+bktBucket+"?logging", nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// TestBktPolicyGetWithNoPolicyAnswers200WithAnEmptyBody records a deviation:
// when the backend reports no policy without an error, the client gets 200 and
// zero bytes behind a JSON content type. AWS answers 404 NoSuchBucketPolicy.
func TestBktPolicyGetWithNoPolicyAnswers200WithAnEmptyBody(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketPolicy", mock.Anything, mock.Anything).Return(&s3.GetBucketPolicyOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetPolicyHandler().Handle, http.MethodGet, "/"+bktBucket+"?policy", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Empty(t, w.Body.String())
}

// TestBktPolicyPutValidatesJSONBeforeForwarding covers handlePutPolicy.
func TestBktPolicyPutValidatesJSONBeforeForwarding(t *testing.T) {
	t.Run("valid_policy_is_forwarded_trimmed", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketPolicy", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketPolicyInput) bool {
			return aws.ToString(in.Policy) == `{"Version":"2012-10-17","Statement":[]}`
		})).Return(&s3.PutBucketPolicyOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy",
			[]byte("  \n{\"Version\":\"2012-10-17\",\"Statement\":[]}\n  "))

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
		backend.AssertExpectations(t)
	})

	t.Run("a_bare_json_scalar_is_accepted_as_a_policy", func(t *testing.T) {
		// Not a policy document at all, but json.Unmarshal into interface{}
		// accepts it, so the proxy forwards it and leaves the refusal to the
		// backend.
		backend := &MockS3Backend{}
		backend.On("PutBucketPolicy", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketPolicyInput) bool {
			return aws.ToString(in.Policy) == "42"
		})).Return(&s3.PutBucketPolicyOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", []byte("42"))

		assert.Equal(t, http.StatusNoContent, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("invalid_json_is_MalformedPolicy", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", []byte("{not json"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		doc := BktparseError(t, w.Body.Bytes())
		assert.Equal(t, "MalformedPolicy", doc.Code)
		assert.Equal(t, "Invalid JSON format", doc.Message)
		backend.AssertNotCalled(t, "PutBucketPolicy", mock.Anything, mock.Anything)
	})

	t.Run("empty_body_is_MalformedPolicy", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "MalformedPolicy", BktparseError(t, w.Body.Bytes()).Code)
	})

	t.Run("unreadable_body", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket+"?policy", nil)
		req.Body = BktfailingReader{}
		req.ContentLength = 8
		w := httptest.NewRecorder()
		h.GetPolicyHandler().Handle(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("PutBucketPolicy", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", []byte("{}"))

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("unsupported_method", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPatch, "/"+bktBucket+"?policy", nil)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		assert.Equal(t, "BucketPolicy_PATCH", BktparseError(t, w.Body.Bytes()).Resource)
	})
}

// TestBktPolicyPutBuffersAnUnboundedBody proves there is no size limit on a
// bucket sub-resource body: the whole request is read into memory and forwarded.
// AWS caps a bucket policy at 20 KB; here a client can make the proxy allocate
// as much as it likes with a single request.
func TestBktPolicyPutBuffersAnUnboundedBody(t *testing.T) {
	const size = 4 << 20 // 4 MiB, far past every S3 sub-resource document limit
	policy := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), size)...)
	policy = append(policy, []byte(`"}`)...)

	backend := &MockS3Backend{}
	backend.On("PutBucketPolicy", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketPolicyInput) bool {
		return len(aws.ToString(in.Policy)) == len(policy)
	})).Return(&s3.PutBucketPolicyOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", policy)

	assert.Equal(t, http.StatusNoContent, w.Code)
	backend.AssertExpectations(t)
}

// TestBktDeletePolicyAnswers204 covers handleDeletePolicy including its error
// path.
func TestBktDeletePolicyAnswers204(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("DeleteBucketPolicy", mock.Anything, mock.MatchedBy(func(in *s3.DeleteBucketPolicyInput) bool {
		return aws.ToString(in.Bucket) == bktBucket
	})).Return(&s3.DeleteBucketPolicyOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetPolicyHandler().Handle, http.MethodDelete, "/"+bktBucket+"?policy", nil)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	backend.AssertExpectations(t)

	t.Run("backend_error", func(t *testing.T) {
		failing := &MockS3Backend{}
		failing.On("DeleteBucketPolicy", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchBucketPolicy", "no policy"))
		fh := BktnewHandlerWith(failing)

		w := Bktserve(fh.GetPolicyHandler().Handle, http.MethodDelete, "/"+bktBucket+"?policy", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchBucketPolicy", BktparseError(t, w.Body.Bytes()).Code)
	})
}

// TestBktLocationOnlyAnswersGET covers the location handler's method arms.
func TestBktLocationOnlyAnswersGET(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketLocation", mock.Anything, mock.Anything).Return(&s3.GetBucketLocationOutput{
		LocationConstraint: s3types.BucketLocationConstraintEuCentral1,
	}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLocationHandler().Handle, http.MethodGet, "/"+bktBucket+"?location", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<LocationConstraint>eu-central-1</LocationConstraint>")
	// Deviation: S3 makes <LocationConstraint> the root element with the S3
	// namespace; here it is nested inside the SDK output struct name.
	assert.True(t, strings.HasPrefix(w.Body.String(), "<GetBucketLocationOutput>"))

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPost, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			w := Bktserve(h.GetLocationHandler().Handle, method, "/"+bktBucket+"?location", nil)
			assert.Equal(t, http.StatusNotImplemented, w.Code)
			if method != http.MethodHead {
				assert.Equal(t, "BucketLocation_"+method, BktparseError(t, w.Body.Bytes()).Resource)
			}
		})
	}
}

// TestBktWriteOnlySubResourcesAreNotImplemented pins the four sub-resources
// whose PUT is a flat refusal, and their DELETE and GET behaviour around it.
func TestBktWriteOnlySubResourcesAreNotImplemented(t *testing.T) {
	cases := []struct {
		name        string
		run         func(h *Handler) http.HandlerFunc
		wantPutRes  string
		deleteCall  string
		hasDelete   bool
		unsupported string
	}{
		{"replication", func(h *Handler) http.HandlerFunc { return h.GetReplicationHandler().Handle },
			"PutBucketReplication", "DeleteBucketReplication", true, "BucketReplication_PATCH"},
		{"website", func(h *Handler) http.HandlerFunc { return h.GetWebsiteHandler().Handle },
			"PutBucketWebsite", "DeleteBucketWebsite", true, "BucketWebsite_PATCH"},
		{"accelerate", func(h *Handler) http.HandlerFunc { return h.GetAccelerateHandler().Handle },
			"PutBucketAccelerateConfiguration", "", false, "BucketAccelerate_DELETE"},
		{"requestPayment", func(h *Handler) http.HandlerFunc { return h.GetRequestPaymentHandler().Handle },
			"PutBucketRequestPayment", "", false, "BucketRequestPayment_DELETE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := BktnewBackend()
			h := BktnewHandlerWith(backend)

			t.Run("PUT_is_501_and_never_reaches_the_backend", func(t *testing.T) {
				w := Bktserve(tc.run(h), http.MethodPut, "/"+bktBucket+"?"+tc.name,
					[]byte("<Configuration><Anything>yes</Anything></Configuration>"))

				assert.Equal(t, http.StatusNotImplemented, w.Code)
				doc := BktparseError(t, w.Body.Bytes())
				assert.Equal(t, "NotImplemented", doc.Code)
				assert.Equal(t, tc.wantPutRes, doc.Resource)
				backend.AssertNotCalled(t, tc.wantPutRes, mock.Anything, mock.Anything)
			})

			t.Run("unsupported_method", func(t *testing.T) {
				method := http.MethodPatch
				if !tc.hasDelete {
					method = http.MethodDelete
				}
				w := Bktserve(tc.run(h), method, "/"+bktBucket+"?"+tc.name, nil)
				assert.Equal(t, http.StatusNotImplemented, w.Code)
				assert.Equal(t, tc.unsupported, BktparseError(t, w.Body.Bytes()).Resource)
			})

			if tc.hasDelete {
				t.Run("DELETE_answers_200_with_an_SDK_struct_body", func(t *testing.T) {
					w := Bktserve(tc.run(h), http.MethodDelete, "/"+bktBucket+"?"+tc.name, nil)
					// Deviation: S3 answers 204 with no body for every one of these.
					assert.Equal(t, http.StatusOK, w.Code)
					assert.Contains(t, w.Body.String(), "<ResultMetadata>")
					backend.AssertCalled(t, tc.deleteCall, mock.Anything, mock.Anything)
				})

				t.Run("DELETE_backend_error", func(t *testing.T) {
					failing := &MockS3Backend{}
					failing.On(tc.deleteCall, mock.Anything, mock.Anything).
						Return(nil, BktapiError("AccessDenied", "Access Denied"))
					fh := BktnewHandlerWith(failing)

					w := Bktserve(tc.run(fh), http.MethodDelete, "/"+bktBucket+"?"+tc.name, nil)
					assert.Equal(t, http.StatusForbidden, w.Code)
				})
			}
		})
	}
}

// TestBktBodyCarryingSubResourcePutsAreRefusedOrSilentlyEmptied is the
// silent-write finding, pinned per sub-resource: versioning, tagging,
// notification and lifecycle can never be configured through the proxy. A body
// is answered 501, and an empty body is forwarded as a call that carries no
// configuration at all.
func TestBktBodyCarryingSubResourcePutsAreRefusedOrSilentlyEmptied(t *testing.T) {
	cases := []struct {
		name     string
		run      func(h *Handler) http.HandlerFunc
		putCall  string
		wantRes  string
		body     string
		emptyArg func(args mock.Arguments) bool
	}{
		{
			name:    "versioning",
			run:     func(h *Handler) http.HandlerFunc { return h.GetVersioningHandler().Handle },
			putCall: "PutBucketVersioning",
			wantRes: "PutBucketVersioning with body parsing",
			body:    `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
			emptyArg: func(args mock.Arguments) bool {
				return args.Get(1).(*s3.PutBucketVersioningInput).VersioningConfiguration == nil
			},
		},
		{
			name:    "tagging",
			run:     func(h *Handler) http.HandlerFunc { return h.GetTaggingHandler().Handle },
			putCall: "PutBucketTagging",
			wantRes: "PutBucketTagging with body parsing",
			body:    `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`,
			emptyArg: func(args mock.Arguments) bool {
				return args.Get(1).(*s3.PutBucketTaggingInput).Tagging == nil
			},
		},
		{
			name:    "notification",
			run:     func(h *Handler) http.HandlerFunc { return h.GetNotificationHandler().Handle },
			putCall: "PutBucketNotificationConfiguration",
			wantRes: "PutBucketNotificationConfiguration with body parsing",
			body:    `<NotificationConfiguration><TopicConfiguration><Topic>arn:aws:sns:x</Topic></TopicConfiguration></NotificationConfiguration>`,
			emptyArg: func(args mock.Arguments) bool {
				return args.Get(1).(*s3.PutBucketNotificationConfigurationInput).NotificationConfiguration == nil
			},
		},
		{
			name:    "lifecycle",
			run:     func(h *Handler) http.HandlerFunc { return h.GetLifecycleHandler().Handle },
			putCall: "PutBucketLifecycleConfiguration",
			wantRes: "PutBucketLifecycleConfiguration with body parsing",
			body:    `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>`,
			emptyArg: func(args mock.Arguments) bool {
				return args.Get(1).(*s3.PutBucketLifecycleConfigurationInput).LifecycleConfiguration == nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_with_body_is_501", func(t *testing.T) {
			backend := &MockS3Backend{}
			h := BktnewHandlerWith(backend)

			w := Bktserve(tc.run(h), http.MethodPut, "/"+bktBucket+"?"+tc.name, []byte(tc.body))

			assert.Equal(t, http.StatusNotImplemented, w.Code)
			doc := BktparseError(t, w.Body.Bytes())
			assert.Equal(t, "NotImplemented", doc.Code)
			assert.Equal(t, tc.wantRes, doc.Resource)
			backend.AssertNotCalled(t, tc.putCall, mock.Anything, mock.Anything)
		})

		t.Run(tc.name+"_with_empty_body_forwards_no_configuration", func(t *testing.T) {
			backend := &MockS3Backend{}
			seen := false
			backend.On(tc.putCall, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				seen = tc.emptyArg(args)
			}).Return(BktemptyPutOutput(tc.putCall), nil)
			h := BktnewHandlerWith(backend)

			w := Bktserve(tc.run(h), http.MethodPut, "/"+bktBucket+"?"+tc.name, nil)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.True(t, seen, "the backend call carried no configuration")
			backend.AssertExpectations(t)
		})

		t.Run(tc.name+"_unreadable_body", func(t *testing.T) {
			backend := &MockS3Backend{}
			h := BktnewHandlerWith(backend)

			req := Bktrequest(http.MethodPut, "/"+bktBucket+"?"+tc.name, nil)
			req.Body = BktfailingReader{}
			req.ContentLength = 12
			w := httptest.NewRecorder()
			tc.run(h)(w, req)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			backend.AssertNotCalled(t, tc.putCall, mock.Anything, mock.Anything)
		})

		t.Run(tc.name+"_backend_error", func(t *testing.T) {
			backend := &MockS3Backend{}
			backend.On(tc.putCall, mock.Anything, mock.Anything).
				Return(nil, BktapiError("AccessDenied", "Access Denied"))
			h := BktnewHandlerWith(backend)

			w := Bktserve(tc.run(h), http.MethodPut, "/"+bktBucket+"?"+tc.name, nil)

			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

// BktemptyPutOutput returns the empty SDK output for one of the PUT
// sub-resource calls, so the table above can stay generic.
func BktemptyPutOutput(call string) interface{} {
	switch call {
	case "PutBucketVersioning":
		return &s3.PutBucketVersioningOutput{}
	case "PutBucketTagging":
		return &s3.PutBucketTaggingOutput{}
	case "PutBucketNotificationConfiguration":
		return &s3.PutBucketNotificationConfigurationOutput{}
	case "PutBucketLifecycleConfiguration":
		return &s3.PutBucketLifecycleConfigurationOutput{}
	default:
		return nil
	}
}

// TestBktTaggingAndLifecycleDeleteShape covers the two remaining DELETE arms
// and pins their response shape.
func TestBktTaggingAndLifecycleDeleteShape(t *testing.T) {
	t.Run("tagging", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketTagging", mock.Anything, mock.MatchedBy(func(in *s3.DeleteBucketTaggingInput) bool {
			return aws.ToString(in.Bucket) == bktBucket
		})).Return(&s3.DeleteBucketTaggingOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetTaggingHandler().Handle, http.MethodDelete, "/"+bktBucket+"?tagging", nil)

		// Deviation: S3 answers 204 with no body.
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "<DeleteBucketTaggingOutput><ResultMetadata></ResultMetadata></DeleteBucketTaggingOutput>", w.Body.String())
		backend.AssertExpectations(t)
	})

	t.Run("tagging_backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketTagging", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchTagSet", "no tags"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetTaggingHandler().Handle, http.MethodDelete, "/"+bktBucket+"?tagging", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchTagSet", BktparseError(t, w.Body.Bytes()).Code)
	})

	t.Run("lifecycle", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketLifecycle", mock.Anything, mock.Anything).
			Return(&s3.DeleteBucketLifecycleOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLifecycleHandler().Handle, http.MethodDelete, "/"+bktBucket+"?lifecycle", nil)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<DeleteBucketLifecycleOutput>")
	})

	t.Run("lifecycle_backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucketLifecycle", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetLifecycleHandler().Handle, http.MethodDelete, "/"+bktBucket+"?lifecycle", nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// TestBktSubResourceUnsupportedMethodsAreNamedInTheError walks the remaining
// default arms so every "BucketX_METHOD" resource string is pinned.
func TestBktSubResourceUnsupportedMethodsAreNamedInTheError(t *testing.T) {
	backend := BktnewBackend()
	h := BktnewHandlerWith(backend)

	cases := []struct {
		run     func() http.HandlerFunc
		method  string
		wantRes string
	}{
		{func() http.HandlerFunc { return h.GetVersioningHandler().Handle }, http.MethodDelete, "BucketVersioning_DELETE"},
		{func() http.HandlerFunc { return h.GetTaggingHandler().Handle }, http.MethodPatch, "BucketTagging_PATCH"},
		{func() http.HandlerFunc { return h.GetNotificationHandler().Handle }, http.MethodDelete, "BucketNotification_DELETE"},
		{func() http.HandlerFunc { return h.GetLifecycleHandler().Handle }, http.MethodPatch, "BucketLifecycle_PATCH"},
		{func() http.HandlerFunc { return h.GetCORSHandler().Handle }, http.MethodPatch, "BucketCORS_PATCH"},
		{func() http.HandlerFunc { return h.GetACLHandler().Handle }, http.MethodDelete, "BucketACL_DELETE"},
	}

	for _, tc := range cases {
		t.Run(tc.wantRes, func(t *testing.T) {
			w := Bktserve(tc.run(), tc.method, "/"+bktBucket, nil)
			assert.Equal(t, http.StatusNotImplemented, w.Code)
			doc := BktparseError(t, w.Body.Bytes())
			assert.Equal(t, "NotImplemented", doc.Code)
			assert.Equal(t, tc.wantRes, doc.Resource)
		})
	}

	for _, call := range BktbaseOpCalls {
		backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
	}
}

// Compile-time check that BktfailingReader is a usable request body.
var _ io.ReadCloser = BktfailingReader{}
