package bucket

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
	return NewHandler(backend, nil, logger, &config.Config{})
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
	// The document a client actually parses. It used to be the aws-sdk-go-v2
	// output struct XML-encoded, so the root element was <GetBucketAclOutput>,
	// there was no S3 namespace, no prolog, and an internal <ResultMetadata>
	// element leaked into every one of these responses.
	assert.True(t, strings.HasPrefix(body, xml.Header+`<AccessControlPolicy xmlns="`),
		"the document is an S3 AccessControlPolicy: %s", body)
	assert.Contains(t, body, "<AccessControlList><Grant>")
	assert.Contains(t, body, `xsi:type="CanonicalUser"`)
	assert.NotContains(t, body, "ResultMetadata")
	assert.NotContains(t, body, "GetBucketAclOutput")
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
	// Every grant the client sends reaches the backend (ADR 0007 D5). The body
	// used to be unmarshalled into types.AccessControlPolicy, which carries no
	// xml struct tags: <Owner> matched its Go field name and survived, every
	// <Grant> did not and was dropped, and the client was answered 200.
	t.Run("grants_in_the_body_reach_the_backend", func(t *testing.T) {
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
		assert.Equal(t, "owner-1", aws.ToString(forwarded.AccessControlPolicy.Owner.ID))
		require.Len(t, forwarded.AccessControlPolicy.Grants, 2,
			"both grants the client sent reach the backend")
		assert.Equal(t, "reader", aws.ToString(forwarded.AccessControlPolicy.Grants[0].Grantee.ID))
		assert.Equal(t, s3types.PermissionRead, forwarded.AccessControlPolicy.Grants[0].Permission)
		assert.Equal(t, "writer", aws.ToString(forwarded.AccessControlPolicy.Grants[1].Grantee.ID))
		assert.Equal(t, s3types.PermissionWrite, forwarded.AccessControlPolicy.Grants[1].Permission)
		backend.AssertExpectations(t)
	})

	// A body that is not an ACL document at all is refused. It used to be
	// accepted: the SDK type has no XMLName, so encoding/xml did not check the
	// root element and anything well-formed was forwarded as an empty ACL.
	t.Run("a_body_that_is_not_an_acl_is_refused", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl",
			[]byte(`<CompletelyUnrelated><Hello>world</Hello></CompletelyUnrelated>`))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
		backend.AssertNotCalled(t, "PutBucketAcl", mock.Anything, mock.Anything)
	})

	// A grantee names itself differently depending on its type, and the xsi:type
	// attribute is what says which. All three shapes have to survive.
	t.Run("every_grantee_shape_survives", func(t *testing.T) {
		body := []byte(`<AccessControlPolicy>
  <Owner><ID>owner-1</ID></Owner>
  <AccessControlList>
    <Grant><Grantee xsi:type="Group" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
			`<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>
    <Grant><Grantee xsi:type="AmazonCustomerByEmail" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
			`<EmailAddress>a@example.test</EmailAddress></Grantee><Permission>WRITE</Permission></Grant>
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
		require.Len(t, forwarded.AccessControlPolicy.Grants, 2)
		assert.Equal(t, s3types.TypeGroup, forwarded.AccessControlPolicy.Grants[0].Grantee.Type)
		assert.Equal(t, "http://acs.amazonaws.com/groups/global/AllUsers",
			aws.ToString(forwarded.AccessControlPolicy.Grants[0].Grantee.URI))
		assert.Equal(t, s3types.TypeAmazonCustomerByEmail, forwarded.AccessControlPolicy.Grants[1].Grantee.Type)
		assert.Equal(t, "a@example.test",
			aws.ToString(forwarded.AccessControlPolicy.Grants[1].Grantee.EmailAddress))
	})

	t.Run("malformed_xml_is_refused_as_an_s3_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetACLHandler().Handle, http.MethodPut, "/"+bktBucket+"?acl", []byte("<AccessControlPolicy>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		// It used to be a plain-text body, which no client SDK can read a <Code>
		// out of (ADR 0007 D5, D8).
		assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
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
		body := w.Body.String()
		// S3 names the elements <AllowedOrigin>/<AllowedMethod> inside
		// <CORSConfiguration>. The SDK struct field names are plural, which is
		// what this used to answer.
		assert.True(t, strings.HasPrefix(body, xml.Header+`<CORSConfiguration xmlns="`), body)
		assert.Contains(t, body, "<AllowedOrigin>https://example.test</AllowedOrigin>")
		assert.Contains(t, body, "<AllowedMethod>GET</AllowedMethod>")
		assert.Contains(t, body, "<MaxAgeSeconds>120</MaxAgeSeconds>")
		assert.NotContains(t, body, "GetBucketCorsOutput")
		assert.NotContains(t, body, "ResultMetadata")
	})

	// Every rule of a real S3 CORSConfiguration reaches the backend. It used to
	// be unmarshalled into aws-sdk-go-v2 types.CORSConfiguration, which has no
	// xml struct tags: S3 names the elements <CORSRule>, <AllowedOrigin>,
	// <AllowedMethod> and the Go fields are the plurals, so nothing matched, the
	// proxy forwarded a configuration with zero rules and answered 200.
	t.Run("a_real_cors_document_reaches_the_backend", func(t *testing.T) {
		body := []byte(`<CORSConfiguration>
  <CORSRule>
    <ID>rule-1</ID>
    <AllowedOrigin>https://a.test</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
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
		require.Len(t, forwarded.CORSConfiguration.CORSRules, 1)
		rule := forwarded.CORSConfiguration.CORSRules[0]
		assert.Equal(t, "rule-1", aws.ToString(rule.ID))
		assert.Equal(t, []string{"https://a.test"}, rule.AllowedOrigins)
		assert.Equal(t, []string{"GET", "PUT"}, rule.AllowedMethods)
		assert.Equal(t, []string{"*"}, rule.AllowedHeaders)
		assert.Equal(t, []string{"ETag"}, rule.ExposeHeaders)
		assert.Equal(t, int32(3000), aws.ToInt32(rule.MaxAgeSeconds))
		backend.AssertExpectations(t)
	})

	// The same parse does accept a document written with the Go field names,
	// which no S3 client emits. Kept as the counter-example that identifies the
	// The mirror image, kept as the counter-example that identifies the cause:
	// a document written with the SDK's Go field names is what used to parse,
	// and now parses to nothing.
	t.Run("go_field_names_no_longer_parse", func(t *testing.T) {
		body := []byte(`<CORSConfiguration>
  <CORSRules>
    <AllowedOrigins>https://a.test</AllowedOrigins>
    <AllowedMethods>GET</AllowedMethods>
    <MaxAgeSeconds>3000</MaxAgeSeconds>
  </CORSRules>
</CORSConfiguration>`)
		backend := &MockS3Backend{}
		backend.On("PutBucketCors", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketCorsInput) bool {
			return in.CORSConfiguration != nil && len(in.CORSConfiguration.CORSRules) == 0
		})).Return(&s3.PutBucketCorsOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", body)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	// Both refusals used to be plain text, which no client SDK can read a <Code>
	// out of: it synthesises one from the status line instead (ADR 0007 D8).
	t.Run("PUT_with_empty_body_is_MalformedXML", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
		backend.AssertNotCalled(t, "PutBucketCors", mock.Anything, mock.Anything)
	})

	t.Run("PUT_with_malformed_xml_is_MalformedXML", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetCORSHandler().Handle, http.MethodPut, "/"+bktBucket+"?cors", []byte("<CORSConfiguration>"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "MalformedXML", BktparseError(t, w.Body.Bytes()).Code)
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
				// An unknown permission with no grantee. A passthrough carries it;
				// the hand-written conversion this replaced had a switch per
				// permission and per grantee type, so both fell through silently
				// and the grant reached the client empty.
				{Permission: s3types.BucketLogsPermission("SOMETHING_ELSE")},
			},
		},
	}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLoggingHandler().Handle, http.MethodGet, "/"+bktBucket+"?logging", nil)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.HasPrefix(body, xml.Header+`<BucketLoggingStatus xmlns="`), body)
	assert.Contains(t, body, "<TargetBucket>logs</TargetBucket>")
	assert.Contains(t, body, "<TargetPrefix>access/</TargetPrefix>")
	// S3 writes xsi:type, not a bare type attribute, and declares the instance
	// namespace on the element.
	assert.Contains(t, body, `xsi:type="CanonicalUser"`)
	assert.Contains(t, body, `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	assert.Contains(t, body, "<DisplayName>User One</DisplayName>")
	assert.Contains(t, body, `xsi:type="AmazonCustomerByEmail"`)
	assert.Contains(t, body, "<EmailAddress>a@b.test</EmailAddress>")
	assert.Contains(t, body, `xsi:type="Group"`)
	assert.Contains(t, body, "<URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>")
	assert.Contains(t, body, "<Permission>FULL_CONTROL</Permission>")
	assert.Contains(t, body, "<Permission>READ</Permission>")
	assert.Contains(t, body, "<Permission>WRITE</Permission>")
	assert.Contains(t, body, "SOMETHING_ELSE",
		"a passthrough carries a permission it does not recognise, rather than dropping it")
}

// TestBktLoggingGetDisabledIsAnEmptyStatus pins the "logging is off" document.
func TestBktLoggingGetDisabledIsAnEmptyStatus(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketLogging", mock.Anything, mock.Anything).Return(&s3.GetBucketLoggingOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetLoggingHandler().Handle, http.MethodGet, "/"+bktBucket+"?logging", nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t,
		xml.Header+`<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></BucketLoggingStatus>`,
		w.Body.String())
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
      <Grant><Grantee xsi:type="CanonicalUser" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ID>u1</ID><DisplayName>User One</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>
      <Grant><Grantee xsi:type="AmazonCustomerByEmail" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><EmailAddress>a@b.test</EmailAddress></Grantee><Permission>READ</Permission></Grant>
      <Grant><Grantee xsi:type="Group" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI></Grantee><Permission>WRITE</Permission></Grant>
      <Grant><Grantee xsi:type="Martian" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ID>x</ID></Grantee><Permission>TELEPORT</Permission></Grant>
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
				// A grantee type and a permission the proxy does not recognise
				// travel to the backend, which is the one that adjudicates them.
				// They used to be dropped to the zero value by a switch per case.
				le.TargetGrants[3].Permission == "TELEPORT" &&
				string(le.TargetGrants[3].Grantee.Type) == "Martian"
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

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
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

// TestBktPolicyGetWithNoPolicyAnswers404 covers handleGetPolicy on the arm where
// the backend reports success and carries no policy document.
func TestBktPolicyGetWithNoPolicyAnswers404(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("GetBucketPolicy", mock.Anything, mock.Anything).Return(&s3.GetBucketPolicyOutput{}, nil)
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.GetPolicyHandler().Handle, http.MethodGet, "/"+bktBucket+"?policy", nil)

	// No policy is a refusal, not a success: ADR 0007 D1 forbids answering success
	// for something the proxy did not honour, and ADR 0008 D7 makes every failure
	// an S3 <Error> document - never a bare status behind an empty body.
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "NoSuchBucketPolicy", BktparseError(t, w.Body.Bytes()).Code)
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

// BktpolicyOfSize builds a syntactically valid policy document with n bytes of
// padding, so a size case is judged on its size and not on its JSON.
func BktpolicyOfSize(n int) []byte {
	policy := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), n)...)
	return append(policy, []byte(`"}`)...)
}

// TestBktPolicyPutBoundsTheBody covers both halves of a bounded sub-resource
// ingest: what fits reaches the backend whole, what does not is refused.
func TestBktPolicyPutBoundsTheBody(t *testing.T) {
	t.Run("within_the_bound_it_is_forwarded_whole", func(t *testing.T) {
		policy := BktpolicyOfSize(8 << 10) // 8 KiB, inside any bound an operator would set

		backend := &MockS3Backend{}
		backend.On("PutBucketPolicy", mock.Anything, mock.MatchedBy(func(in *s3.PutBucketPolicyInput) bool {
			return aws.ToString(in.Policy) == string(policy)
		})).Return(&s3.PutBucketPolicyOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", policy)

		// ADR 0007 D5: a document the proxy accepts arrives at the backend in full.
		// A bound may refuse a body, it may never truncate or mangle one.
		assert.Equal(t, http.StatusNoContent, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("above_the_bound_it_is_refused_before_it_is_read", func(t *testing.T) {
		policy := BktpolicyOfSize(4 << 20) // 4 MiB, past any sub-resource ingest bound

		// BktnewBackend, not a bare mock: the forwarded call this must not make
		// then reads as the assertion below and not as a panic on the package.
		backend := BktnewBackend()
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.GetPolicyHandler().Handle, http.MethodPut, "/"+bktBucket+"?policy", policy)

		// ADR 0024 D4 wants in-flight memory bounded and configured, and ADR 0011 D5
		// refuses an oversized body before it is read instead of buffering it first.
		// Which bound, and EntityTooLarge vs MalformedPolicy, is still an open decision.
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "EntityTooLarge", BktparseError(t, w.Body.Bytes()).Code)
		backend.AssertNotCalled(t, "PutBucketPolicy", mock.Anything, mock.Anything)
	})
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
	// S3 makes <LocationConstraint> the root element with the S3 namespace. It
	// used to be nested inside the SDK output struct name.
	assert.True(t, strings.HasPrefix(w.Body.String(),
		xml.Header+`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`), w.Body.String())
	assert.Contains(t, w.Body.String(), ">eu-central-1</LocationConstraint>")
	assert.NotContains(t, w.Body.String(), "GetBucketLocationOutput")

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
				t.Run("DELETE_answers_204_with_no_body", func(t *testing.T) {
					w := Bktserve(tc.run(h), http.MethodDelete, "/"+bktBucket+"?"+tc.name, nil)
					// As S3. It used to answer 200 with the SDK output struct
					// marshalled, internal <ResultMetadata> element and all.
					assert.Equal(t, http.StatusNoContent, w.Code)
					assert.Empty(t, w.Body.String())
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

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
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

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
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
