package bucket

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// BktbaseOpCalls are the backend calls the base bucket operations make. A
// sub-resource request that reaches any of them is the routing defect that once
// made DELETE /bucket?encryption delete the whole bucket (ADR 0007).
var BktbaseOpCalls = []string{"CreateBucket", "DeleteBucket", "ListObjects", "ListObjectsV2"}

// BkterrorDoc is the S3 <Error> document the proxy renders for a refusal.
type BkterrorDoc struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

// BktparseError decodes an S3 error document and fails the test if the body is
// not one. Used to prove a refusal is a real S3 answer, not an HTML/plain-text
// page a client cannot branch on.
func BktparseError(t *testing.T, body []byte) BkterrorDoc {
	t.Helper()
	var doc BkterrorDoc
	require.NoError(t, xml.Unmarshal(body, &doc), "body is not an S3 <Error> document: %s", string(body))
	return doc
}

// BktnewBackend answers every bucket call in this package with an empty
// success. A misrouted request then shows up as an unexpected backend call the
// assertions can name, instead of a panic on a missing expectation.
func BktnewBackend() *MockS3Backend {
	m := &MockS3Backend{}
	m.On("GetBucketAcl", mock.Anything, mock.Anything).Return(&s3.GetBucketAclOutput{}, nil).Maybe()
	m.On("PutBucketAcl", mock.Anything, mock.Anything).Return(&s3.PutBucketAclOutput{}, nil).Maybe()
	m.On("GetBucketCors", mock.Anything, mock.Anything).Return(&s3.GetBucketCorsOutput{}, nil).Maybe()
	m.On("PutBucketCors", mock.Anything, mock.Anything).Return(&s3.PutBucketCorsOutput{}, nil).Maybe()
	m.On("DeleteBucketCors", mock.Anything, mock.Anything).Return(&s3.DeleteBucketCorsOutput{}, nil).Maybe()
	m.On("GetBucketPolicy", mock.Anything, mock.Anything).Return(&s3.GetBucketPolicyOutput{}, nil).Maybe()
	m.On("PutBucketPolicy", mock.Anything, mock.Anything).Return(&s3.PutBucketPolicyOutput{}, nil).Maybe()
	m.On("DeleteBucketPolicy", mock.Anything, mock.Anything).Return(&s3.DeleteBucketPolicyOutput{}, nil).Maybe()
	m.On("GetBucketLocation", mock.Anything, mock.Anything).Return(&s3.GetBucketLocationOutput{}, nil).Maybe()
	m.On("GetBucketLogging", mock.Anything, mock.Anything).Return(&s3.GetBucketLoggingOutput{}, nil).Maybe()
	m.On("PutBucketLogging", mock.Anything, mock.Anything).Return(&s3.PutBucketLoggingOutput{}, nil).Maybe()
	m.On("GetBucketVersioning", mock.Anything, mock.Anything).Return(&s3.GetBucketVersioningOutput{}, nil).Maybe()
	m.On("PutBucketVersioning", mock.Anything, mock.Anything).Return(&s3.PutBucketVersioningOutput{}, nil).Maybe()
	m.On("GetBucketTagging", mock.Anything, mock.Anything).Return(&s3.GetBucketTaggingOutput{}, nil).Maybe()
	m.On("PutBucketTagging", mock.Anything, mock.Anything).Return(&s3.PutBucketTaggingOutput{}, nil).Maybe()
	m.On("DeleteBucketTagging", mock.Anything, mock.Anything).Return(&s3.DeleteBucketTaggingOutput{}, nil).Maybe()
	m.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).
		Return(&s3.GetBucketNotificationConfigurationOutput{}, nil).Maybe()
	m.On("PutBucketNotificationConfiguration", mock.Anything, mock.Anything).
		Return(&s3.PutBucketNotificationConfigurationOutput{}, nil).Maybe()
	m.On("GetBucketLifecycleConfiguration", mock.Anything, mock.Anything).
		Return(&s3.GetBucketLifecycleConfigurationOutput{}, nil).Maybe()
	m.On("PutBucketLifecycleConfiguration", mock.Anything, mock.Anything).
		Return(&s3.PutBucketLifecycleConfigurationOutput{}, nil).Maybe()
	m.On("DeleteBucketLifecycle", mock.Anything, mock.Anything).Return(&s3.DeleteBucketLifecycleOutput{}, nil).Maybe()
	m.On("GetBucketReplication", mock.Anything, mock.Anything).Return(&s3.GetBucketReplicationOutput{}, nil).Maybe()
	m.On("PutBucketReplication", mock.Anything, mock.Anything).Return(&s3.PutBucketReplicationOutput{}, nil).Maybe()
	m.On("DeleteBucketReplication", mock.Anything, mock.Anything).Return(&s3.DeleteBucketReplicationOutput{}, nil).Maybe()
	m.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{}, nil).Maybe()
	m.On("PutBucketWebsite", mock.Anything, mock.Anything).Return(&s3.PutBucketWebsiteOutput{}, nil).Maybe()
	m.On("DeleteBucketWebsite", mock.Anything, mock.Anything).Return(&s3.DeleteBucketWebsiteOutput{}, nil).Maybe()
	m.On("GetBucketAccelerateConfiguration", mock.Anything, mock.Anything).
		Return(&s3.GetBucketAccelerateConfigurationOutput{}, nil).Maybe()
	m.On("PutBucketAccelerateConfiguration", mock.Anything, mock.Anything).
		Return(&s3.PutBucketAccelerateConfigurationOutput{}, nil).Maybe()
	m.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{}, nil).Maybe()
	m.On("PutBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.PutBucketRequestPaymentOutput{}, nil).Maybe()
	// The base operations: registered so a fall-through succeeds instead of
	// panicking. AssertNotCalled is what has to report it.
	m.On("CreateBucket", mock.Anything, mock.Anything).Return(&s3.CreateBucketOutput{}, nil).Maybe()
	m.On("DeleteBucket", mock.Anything, mock.Anything).Return(&s3.DeleteBucketOutput{}, nil).Maybe()
	m.On("ListObjects", mock.Anything, mock.Anything).Return(&s3.ListObjectsOutput{}, nil).Maybe()
	m.On("ListObjectsV2", mock.Anything, mock.Anything).Return(&s3.ListObjectsV2Output{}, nil).Maybe()
	return m
}

// BktforeignHits counts requests that a mirrored route hands to a handler owned
// by another package (multipart list uploads, delete multiple objects). Those
// are correct destinations, just not this package's.
type BktforeignHits struct {
	Uploads int
	Delete  int
}

// BktnewRouter mirrors the bucket-related route table of internal/proxy/router.go.
// The bucket package cannot import internal/proxy (that package imports this
// one), so the registrations are repeated here. They must stay in step with
// router.go lines 48-90; a drift shows up as a matrix cell whose status changes.
func BktnewRouter(backend *MockS3Backend) (*mux.Router, *BktforeignHits) {
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	h := NewHandler(backend, nil, logger, &config.Config{})

	hits := &BktforeignHits{}
	r := mux.NewRouter()

	r.HandleFunc("/{bucket}", h.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	r.HandleFunc("/{bucket}", h.GetCORSHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("cors", "")
	r.HandleFunc("/{bucket}", h.GetPolicyHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("policy", "")
	r.HandleFunc("/{bucket}", h.GetLocationHandler().Handle).Methods("GET").Queries("location", "")
	r.HandleFunc("/{bucket}", h.GetLoggingHandler().Handle).Methods("GET", "PUT").Queries("logging", "")
	r.HandleFunc("/{bucket}", h.GetVersioningHandler().Handle).Methods("GET", "PUT").Queries("versioning", "")
	r.HandleFunc("/{bucket}", h.GetNotificationHandler().Handle).Methods("GET", "PUT").Queries("notification", "")
	r.HandleFunc("/{bucket}", h.GetTaggingHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	r.HandleFunc("/{bucket}", h.GetLifecycleHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("lifecycle", "")
	r.HandleFunc("/{bucket}", h.GetReplicationHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("replication", "")
	r.HandleFunc("/{bucket}", h.GetWebsiteHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("website", "")
	r.HandleFunc("/{bucket}", h.GetAccelerateHandler().Handle).Methods("GET", "PUT").Queries("accelerate", "")
	r.HandleFunc("/{bucket}", h.GetRequestPaymentHandler().Handle).Methods("GET", "PUT").Queries("requestPayment", "")

	// Routes owned by other packages, stubbed: only the destination matters here.
	r.HandleFunc("/{bucket}", func(w http.ResponseWriter, _ *http.Request) {
		hits.Uploads++
		w.WriteHeader(http.StatusOK)
	}).Methods("GET").Queries("uploads", "")
	r.HandleFunc("/{bucket}", func(w http.ResponseWriter, _ *http.Request) {
		hits.Delete++
		w.WriteHeader(http.StatusOK)
	}).Methods("POST").Queries("delete", "")

	r.HandleFunc("/{bucket}", h.Handle).Methods("GET", "PUT", "DELETE", "HEAD")
	r.HandleFunc("/{bucket}/", h.Handle).Methods("GET", "PUT", "DELETE", "HEAD")

	return r, hits
}

// TestBktSubResourceMethodMatrixNeverReachesBaseBucketOperation walks every
// bucket sub-resource query parameter the router knows, crossed with GET, PUT
// and DELETE, through a mirror of the production route table.
//
// Two things are asserted for every one of the 39 cells:
//   - the status is exactly what the code produces today - a real answer for a
//     routed method, an explicit S3 refusal for an unrouted one;
//   - none of CreateBucket, DeleteBucket, ListObjects or ListObjectsV2 was
//     called. That is the ADR 0007 guard: a sub-resource request must
//     never fall through to the base bucket operation of its HTTP method.
func TestBktSubResourceMethodMatrixNeverReachesBaseBucketOperation(t *testing.T) {
	const (
		bktRealAnswer = "real answer"
		bktRefusal    = "explicit refusal"
	)

	type cell struct {
		method     string
		wantStatus int
		wantCode   string // S3 <Code> for a refusal, empty for a real answer
		kind       string
		note       string
	}

	// Bodies are empty on purpose: an empty PUT is the shape most likely to be
	// mistaken for "nothing to do, report success".
	matrix := []struct {
		param string
		cells []cell
	}{
		{"acl", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusOK, "", bktRealAnswer, "no ACL header and no body: forwarded as an empty PutBucketAcl"},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
		{"cors", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusBadRequest, "", bktRefusal, "plain-text refusal, not an S3 <Error> document"},
			{http.MethodDelete, http.StatusNoContent, "", bktRealAnswer, ""},
		}},
		{"policy", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusBadRequest, "MalformedPolicy", bktRefusal, ""},
			{http.MethodDelete, http.StatusNoContent, "", bktRealAnswer, ""},
		}},
		{"location", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
		{"logging", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusBadRequest, "MalformedXML", bktRefusal, ""},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, "handleDeleteLogging is unreachable through the router"},
		}},
		{"versioning", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusOK, "", bktRealAnswer, "empty body is forwarded with no VersioningConfiguration"},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
		{"notification", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusOK, "", bktRealAnswer, "empty body is forwarded with no NotificationConfiguration"},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
		{"tagging", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusOK, "", bktRealAnswer, "empty body is forwarded with no TagSet"},
			{http.MethodDelete, http.StatusOK, "", bktRealAnswer, "AWS answers 204 with an empty body"},
		}},
		{"lifecycle", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusOK, "", bktRealAnswer, "empty body is forwarded with no LifecycleConfiguration"},
			{http.MethodDelete, http.StatusOK, "", bktRealAnswer, "AWS answers 204 with an empty body"},
		}},
		{"replication", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusNotImplemented, "NotImplemented", bktRefusal, ""},
			{http.MethodDelete, http.StatusOK, "", bktRealAnswer, "AWS answers 204 with an empty body"},
		}},
		{"website", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusNotImplemented, "NotImplemented", bktRefusal, ""},
			{http.MethodDelete, http.StatusOK, "", bktRealAnswer, "AWS answers 204 with an empty body"},
		}},
		{"accelerate", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusNotImplemented, "NotImplemented", bktRefusal, ""},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
		{"requestPayment", []cell{
			{http.MethodGet, http.StatusOK, "", bktRealAnswer, ""},
			{http.MethodPut, http.StatusNotImplemented, "NotImplemented", bktRefusal, ""},
			{http.MethodDelete, http.StatusMethodNotAllowed, "MethodNotAllowed", bktRefusal, ""},
		}},
	}

	seen := 0
	for _, sub := range matrix {
		for _, c := range sub.cells {
			seen++
			t.Run(c.method+"_"+sub.param, func(t *testing.T) {
				backend := BktnewBackend()
				router, hits := BktnewRouter(backend)

				req := httptest.NewRequest(c.method, "/test-bucket?"+sub.param, nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, c.wantStatus, w.Code, "unexpected status; note: %s", c.note)

				// The ADR 0007 guard: no base bucket operation may run.
				for _, call := range BktbaseOpCalls {
					backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
				}
				assert.Zero(t, hits.Uploads, "must not reach the multipart listing route")
				assert.Zero(t, hits.Delete, "must not reach the delete-objects route")

				switch c.kind {
				case bktRefusal:
					assert.GreaterOrEqual(t, w.Code, 400, "a refusal must not use a 2xx status")
					if c.wantCode != "" {
						doc := BktparseError(t, w.Body.Bytes())
						assert.Equal(t, c.wantCode, doc.Code)
					}
				case bktRealAnswer:
					assert.Less(t, w.Code, 400, "a real answer must use a 2xx status")
				}
			})
		}
	}
	require.Equal(t, 39, seen, "13 sub-resources x 3 methods must all be walked")
}

// TestBktUnroutedSubResourceIsRefusedThroughTheRouter is the ADR 0007
// regression guard at router level: a sub-resource query parameter that has no
// route at all must be refused with 501 NotImplemented, on every method the
// base bucket route accepts, and must never run the base operation.
func TestBktUnroutedSubResourceIsRefusedThroughTheRouter(t *testing.T) {
	// Every bucket sub-resource S3 defines that this proxy does not route.
	unrouted := []string{
		"encryption", "object-lock", "publicAccessBlock", "ownershipControls",
		"versions", "inventory", "metrics", "analytics", "intelligent-tiering",
		"policyStatus", "cors-preflight", "attributes",
	}

	for _, param := range unrouted {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
			t.Run(method+"_"+param, func(t *testing.T) {
				backend := BktnewBackend()
				router, hits := BktnewRouter(backend)

				req := httptest.NewRequest(method, "/test-bucket?"+param, nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusNotImplemented, w.Code)
				for _, call := range BktbaseOpCalls {
					backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
				}
				assert.Zero(t, hits.Uploads)
				assert.Zero(t, hits.Delete)

				if method != http.MethodHead {
					doc := BktparseError(t, w.Body.Bytes())
					assert.Equal(t, "NotImplemented", doc.Code)
					assert.Equal(t, "BucketSubResource", doc.Resource)
					assert.Equal(t, "BucketSubResource operation is not yet implemented", doc.Message)
				}
			})
		}
	}
}

// TestBktUnroutedSubResourceSurvivesBaseParameterCompany pins that mixing an
// unimplemented sub-resource into an otherwise legitimate listing query still
// refuses. The parameter check walks a map, so the loop order is random; the
// refusal must not depend on it.
func TestBktUnroutedSubResourceSurvivesBaseParameterCompany(t *testing.T) {
	for i := 0; i < 25; i++ {
		backend := BktnewBackend()
		router, _ := BktnewRouter(backend)

		req := httptest.NewRequest(http.MethodGet,
			"/test-bucket?list-type=2&prefix=a&max-keys=10&encryption&x-id=ListObjectsV2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotImplemented, w.Code)
		backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	}
}

// TestBktKnownSubResourceWithUnroutedMethodIsMethodNotAllowed pins the other
// half of the two-stage check in Handle: a sub-resource that does have a route
// but not for this method answers 405, and keeps answering 405 when an
// unimplemented parameter rides along.
func TestBktKnownSubResourceWithUnroutedMethodIsMethodNotAllowed(t *testing.T) {
	cases := []struct {
		name   string
		method string
		url    string
	}{
		{"delete_acl", http.MethodDelete, "/test-bucket?acl"},
		{"delete_uploads", http.MethodDelete, "/test-bucket?uploads"},
		{"delete_delete", http.MethodDelete, "/test-bucket?delete"},
		{"put_location", http.MethodPut, "/test-bucket?location"},
		{"head_tagging", http.MethodHead, "/test-bucket?tagging"},
		{"delete_acl_with_unrouted_company", http.MethodDelete, "/test-bucket?acl&encryption"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 25; i++ {
				backend := BktnewBackend()
				router, _ := BktnewRouter(backend)

				req := httptest.NewRequest(tc.method, tc.url, nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				require.Equal(t, http.StatusMethodNotAllowed, w.Code)
				for _, call := range BktbaseOpCalls {
					backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
				}
			}
		})
	}

	t.Run("body_is_an_s3_error_document", func(t *testing.T) {
		backend := BktnewBackend()
		router, _ := BktnewRouter(backend)

		req := httptest.NewRequest(http.MethodDelete, "/test-bucket?acl", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
		assert.True(t, strings.HasPrefix(w.Body.String(), xml.Header),
			"error documents carry the XML prolog")
		doc := BktparseError(t, w.Body.Bytes())
		assert.Equal(t, "MethodNotAllowed", doc.Code)
		assert.Equal(t, "The specified method is not allowed against this resource.", doc.Message)
	})
}

// TestBktSubResourceKeepsItsRouteWhateverTheQueryValue pins that ?acl, ?acl=
// and ?acl=1 all reach the sub-resource handler. mux matches Queries("acl", "")
// on the key alone, which is what S3 does too: the value of a sub-resource
// marker is ignored. If a future route tightened this to an exact empty value,
// ?acl=1 would fall through to the base route and be answered as a listing.
func TestBktSubResourceKeepsItsRouteWhateverTheQueryValue(t *testing.T) {
	cases := []struct {
		url      string
		wantCall string
	}{
		{"/test-bucket?acl", "GetBucketAcl"},
		{"/test-bucket?acl=", "GetBucketAcl"},
		{"/test-bucket?acl=1", "GetBucketAcl"},
		{"/test-bucket?tagging=yes", "GetBucketTagging"},
		{"/test-bucket?location=x", "GetBucketLocation"},
	}

	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			backend := BktnewBackend()
			router, _ := BktnewRouter(backend)

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			backend.AssertCalled(t, tc.wantCall, mock.Anything, mock.Anything)
			for _, call := range BktbaseOpCalls {
				backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
			}
		})
	}
}

// TestBktBaseBucketParametersReachTheBaseOperation is the guard in the other
// direction: the allowlist must not turn a normal listing into a refusal. Every
// parameter in baseBucketParams has to keep reaching the backend.
func TestBktBaseBucketParametersReachTheBaseOperation(t *testing.T) {
	params := []string{
		"prefix=a/", "delimiter=/", "max-keys=10",
		"continuation-token=tok", "marker=m", "encoding-type=url",
		"start-after=k", "fetch-owner=true", "x-id=ListObjectsV2",
		"X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Credential=c", "X-Amz-Date=d",
		"X-Amz-Expires=60", "X-Amz-SignedHeaders=host", "X-Amz-Signature=sig",
		"X-Amz-Security-Token=t",
	}

	for _, p := range params {
		t.Run(p, func(t *testing.T) {
			backend := BktnewBackend()
			router, _ := BktnewRouter(backend)

			req := httptest.NewRequest(http.MethodGet, "/test-bucket?"+p, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			// Without list-type=2 the handler takes the ListObjects (V1) branch.
			backend.AssertCalled(t, "ListObjects", mock.Anything, mock.Anything)
		})
	}

	t.Run("list-type=2", func(t *testing.T) {
		backend := BktnewBackend()
		router, _ := BktnewRouter(backend)

		req := httptest.NewRequest(http.MethodGet, "/test-bucket?list-type=2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})

	t.Run("all_of_them_at_once", func(t *testing.T) {
		backend := BktnewBackend()
		router, _ := BktnewRouter(backend)

		req := httptest.NewRequest(http.MethodGet, "/test-bucket?list-type=2&"+strings.Join(params, "&"), nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})
}

// TestBktBaseRouteMethodsWithoutQuery pins what the four base methods answer on
// a bare bucket URL, including the trailing-slash form router.go registers.
func TestBktBaseRouteMethodsWithoutQuery(t *testing.T) {
	cases := []struct {
		method     string
		url        string
		wantStatus int
		wantCall   string
	}{
		{http.MethodGet, "/test-bucket", http.StatusOK, "ListObjects"},
		{http.MethodGet, "/test-bucket/", http.StatusOK, "ListObjects"},
		{http.MethodPut, "/test-bucket", http.StatusOK, "CreateBucket"},
		{http.MethodDelete, "/test-bucket", http.StatusNoContent, "DeleteBucket"},
		{http.MethodHead, "/test-bucket", http.StatusOK, "ListObjectsV2"},
	}

	for _, tc := range cases {
		t.Run(tc.method+"_"+tc.url, func(t *testing.T) {
			backend := BktnewBackend()
			router, _ := BktnewRouter(backend)

			req := httptest.NewRequest(tc.method, tc.url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			backend.AssertCalled(t, tc.wantCall, mock.Anything, mock.Anything)
		})
	}
}

// TestBktHandleRejectsMethodsTheBaseRouteDoesNotServe covers the default arm of
// handleBaseBucketOperations, which the router itself never reaches because the
// base route is registered for GET/PUT/DELETE/HEAD only.
func TestBktHandleRejectsMethodsTheBaseRouteDoesNotServe(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			backend := BktnewBackend()
			logger := logrus.NewEntry(logrus.New())
			logger.Logger.SetLevel(logrus.PanicLevel)
			h := NewHandler(backend, nil, logger, &config.Config{})

			req := httptest.NewRequest(method, "/test-bucket", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()
			h.Handle(w, req)

			assert.Equal(t, http.StatusNotImplemented, w.Code)
			doc := BktparseError(t, w.Body.Bytes())
			assert.Equal(t, "NotImplemented", doc.Code)
			assert.Equal(t, "Bucket_"+method, doc.Resource)
			for _, call := range BktbaseOpCalls {
				backend.AssertNotCalled(t, call, mock.Anything, mock.Anything)
			}
		})
	}
}
