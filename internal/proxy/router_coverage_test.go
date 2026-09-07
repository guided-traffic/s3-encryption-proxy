package proxy

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RtPxrouter builds the real router from setupRoutes. The handlers behind it are
// constructed with a nil backend, which is fine for route matching and for the
// error paths that answer before touching S3.
func RtPxrouter(t *testing.T, monitoring bool) (*Server, *mux.Router) {
	t.Helper()
	server := RtPxserver(t)
	server.config.Monitoring.Enabled = monitoring
	router := mux.NewRouter()
	server.setupRoutes(router)
	return server, router
}

// RtPxhandlerName returns the qualified function name behind a matched route.
func RtPxhandlerName(t *testing.T, r *mux.Router, req *http.Request) string {
	t.Helper()
	var match mux.RouteMatch
	require.True(t, r.Match(req, &match), "%s %s must match a route", req.Method, req.URL.RequestURI())
	require.NotNil(t, match.Route)
	h := match.Route.GetHandler()
	require.NotNil(t, h)
	return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
}

// RtPxmatch returns the route match for a request, or fails.
func RtPxmatch(t *testing.T, r *mux.Router, req *http.Request) mux.RouteMatch {
	t.Helper()
	var match mux.RouteMatch
	require.True(t, r.Match(req, &match), "%s %s must match a route", req.Method, req.URL.RequestURI())
	return match
}

// Every documented S3 request has to reach the handler that implements it. mux
// matches in registration order, so a route added in the wrong place silently
// takes over another operation - that is how UploadPartCopy once became a
// zero-byte UploadPart.
func TestRtPxRouteDispatch(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name    string
		method  string
		target  string
		headers map[string]string
		want    string
	}{
		{name: "ListBuckets", method: "GET", target: "/", want: "root.(*Handler).HandleListBuckets"},

		{name: "GetBucketAcl", method: "GET", target: "/b?acl=", want: "bucket.(*ACLHandler).Handle"},
		{name: "PutBucketAcl", method: "PUT", target: "/b?acl=", want: "bucket.(*ACLHandler).Handle"},
		{name: "GetBucketCors", method: "GET", target: "/b?cors=", want: "bucket.(*CORSHandler).Handle"},
		{name: "DeleteBucketCors", method: "DELETE", target: "/b?cors=", want: "bucket.(*CORSHandler).Handle"},
		{name: "GetBucketPolicy", method: "GET", target: "/b?policy=", want: "bucket.(*PolicyHandler).Handle"},
		{name: "DeleteBucketPolicy", method: "DELETE", target: "/b?policy=", want: "bucket.(*PolicyHandler).Handle"},
		{name: "GetBucketLocation", method: "GET", target: "/b?location=", want: "bucket.(*LocationHandler).Handle"},
		{name: "GetBucketLogging", method: "GET", target: "/b?logging=", want: "bucket.(*LoggingHandler).Handle"},
		{name: "GetBucketVersioning", method: "GET", target: "/b?versioning=", want: "bucket.(*VersioningHandler).Handle"},
		{name: "PutBucketVersioning", method: "PUT", target: "/b?versioning=", want: "bucket.(*VersioningHandler).Handle"},
		{name: "GetBucketNotification", method: "GET", target: "/b?notification=", want: "bucket.(*NotificationHandler).Handle"},
		{name: "GetBucketTagging", method: "GET", target: "/b?tagging=", want: "bucket.(*TaggingHandler).Handle"},
		{name: "DeleteBucketTagging", method: "DELETE", target: "/b?tagging=", want: "bucket.(*TaggingHandler).Handle"},
		{name: "GetBucketLifecycle", method: "GET", target: "/b?lifecycle=", want: "bucket.(*LifecycleHandler).Handle"},
		{name: "GetBucketReplication", method: "GET", target: "/b?replication=", want: "bucket.(*ReplicationHandler).Handle"},
		{name: "GetBucketWebsite", method: "GET", target: "/b?website=", want: "bucket.(*WebsiteHandler).Handle"},
		{name: "GetBucketAccelerate", method: "GET", target: "/b?accelerate=", want: "bucket.(*AccelerateHandler).Handle"},
		{name: "GetBucketRequestPayment", method: "GET", target: "/b?requestPayment=", want: "bucket.(*RequestPaymentHandler).Handle"},

		{name: "CreateMultipartUpload", method: "POST", target: "/b/k?uploads=", want: "multipart.(*CreateHandler).Handle"},
		{name: "UploadPart", method: "PUT", target: "/b/k?partNumber=1&uploadId=u", want: "multipart.(*UploadHandler).Handle"},
		{
			name:    "UploadPartCopy wins over UploadPart",
			method:  "PUT",
			target:  "/b/k?partNumber=1&uploadId=u",
			headers: map[string]string{"x-amz-copy-source": "/src/key"},
			want:    "multipart.(*CopyHandler).Handle",
		},
		{name: "CompleteMultipartUpload", method: "POST", target: "/b/k?uploadId=u", want: "multipart.(*CompleteHandler).Handle"},
		{name: "AbortMultipartUpload", method: "DELETE", target: "/b/k?uploadId=u", want: "multipart.(*AbortHandler).Handle"},
		{name: "ListParts", method: "GET", target: "/b/k?uploadId=u", want: "multipart.(*ListHandler).HandleListParts"},
		{name: "ListMultipartUploads", method: "GET", target: "/b?uploads=", want: "multipart.(*ListHandler).HandleListMultipartUploads"},

		{name: "GetObjectAcl", method: "GET", target: "/b/k?acl=", want: "object.(*ACLHandler).Handle"},
		{name: "GetObjectTagging", method: "GET", target: "/b/k?tagging=", want: "object.(*TaggingHandler).Handle"},
		{name: "DeleteObjectTagging", method: "DELETE", target: "/b/k?tagging=", want: "object.(*TaggingHandler).Handle"},
		{name: "GetObjectLegalHold", method: "GET", target: "/b/k?legal-hold=", want: "object.(*Handler).HandleObjectLegalHold"},
		{name: "GetObjectRetention", method: "GET", target: "/b/k?retention=", want: "object.(*Handler).HandleObjectRetention"},
		{name: "GetObjectTorrent", method: "GET", target: "/b/k?torrent=", want: "object.(*Handler).HandleObjectTorrent"},
		{name: "SelectObjectContent", method: "POST", target: "/b/k?select=&select-type=2", want: "object.(*Handler).HandleSelectObjectContent"},
		{name: "DeleteObjects", method: "POST", target: "/b?delete=", want: "object.(*Handler).HandleDeleteObjects"},

		{name: "ListObjects", method: "GET", target: "/b", want: "bucket.(*Handler).Handle"},
		{name: "ListObjectsV2", method: "GET", target: "/b?list-type=2&prefix=a/", want: "bucket.(*Handler).Handle"},
		{name: "CreateBucket", method: "PUT", target: "/b", want: "bucket.(*Handler).Handle"},
		{name: "DeleteBucket", method: "DELETE", target: "/b", want: "bucket.(*Handler).Handle"},
		{name: "HeadBucket", method: "HEAD", target: "/b", want: "bucket.(*Handler).Handle"},
		{name: "ListObjects with trailing slash", method: "GET", target: "/b/", want: "bucket.(*Handler).Handle"},

		{name: "GetObject", method: "GET", target: "/b/k", want: "object.(*Handler).Handle"},
		{name: "PutObject", method: "PUT", target: "/b/k", want: "object.(*Handler).Handle"},
		{name: "DeleteObject", method: "DELETE", target: "/b/k", want: "object.(*Handler).Handle"},
		{name: "HeadObject", method: "HEAD", target: "/b/k", want: "object.(*Handler).Handle"},
		{name: "GetObject of a versioned object", method: "GET", target: "/b/k?versionId=v1", want: "object.(*Handler).Handle"},
		{name: "CopyObject", method: "PUT", target: "/b/k", headers: map[string]string{"x-amz-copy-source": "/src/key"}, want: "object.(*Handler).Handle"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Contains(t, RtPxhandlerName(t, router, req), tc.want)
		})
	}
}

// A bucket sub-resource must never be executed as a plain bucket operation:
// that is how DELETE /bucket?policy once deleted the bucket. For the methods a
// sub-resource does not support, the base handler has to refuse instead.
func TestRtPxBucketSubResourceNeverReachesBaseBucketHandler(t *testing.T) {
	_, router := RtPxrouter(t, false)

	subResources := map[string][]string{
		"acl":            {"GET", "PUT"},
		"cors":           {"GET", "PUT", "DELETE"},
		"policy":         {"GET", "PUT", "DELETE"},
		"location":       {"GET"},
		"logging":        {"GET", "PUT"},
		"versioning":     {"GET", "PUT"},
		"notification":   {"GET", "PUT"},
		"tagging":        {"GET", "PUT", "DELETE"},
		"lifecycle":      {"GET", "PUT", "DELETE"},
		"replication":    {"GET", "PUT", "DELETE"},
		"website":        {"GET", "PUT", "DELETE"},
		"accelerate":     {"GET", "PUT"},
		"requestPayment": {"GET", "PUT"},
		"uploads":        {"GET"},
		"delete":         {"POST"},
	}

	for param, methods := range subResources {
		for _, method := range methods {
			t.Run(method+"_"+param, func(t *testing.T) {
				req := httptest.NewRequest(method, "/test-bucket?"+param+"=", nil)
				name := RtPxhandlerName(t, router, req)
				assert.NotContains(t, name, "bucket.(*Handler).Handle",
					"%s /bucket?%s must not run the base bucket operation", method, param)
			})
		}
	}
}

// The unsupported combinations reach the base handler on purpose; it has to
// refuse them rather than run a different operation. Both requests are signed,
// so this runs through the real router with the whole middleware chain.
func TestRtPxBaseBucketHandlerRefusesSubResourceRequests(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantCode   string
	}{
		{
			// DELETE has no ?acl route, so it lands on the base handler, which
			// must not fall through to DeleteBucket.
			name:       "DELETE with a known sub-resource",
			method:     http.MethodDelete,
			target:     "/test-bucket?acl=",
			wantStatus: http.StatusMethodNotAllowed,
			wantCode:   "MethodNotAllowed",
		},
		{
			// An unimplemented sub-resource must not be executed as ListObjects.
			name:       "GET with an unimplemented sub-resource",
			method:     http.MethodGet,
			target:     "/test-bucket?encryption=",
			wantStatus: http.StatusNotImplemented,
			wantCode:   "NotImplemented",
		},
		{
			name:       "DELETE with an unimplemented sub-resource must not delete the bucket",
			method:     http.MethodDelete,
			target:     "/test-bucket?publicAccessBlock=",
			wantStatus: http.StatusNotImplemented,
			wantCode:   "NotImplemented",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, RtPxsignedRequest(t, tc.method, tc.target))

			require.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

			var doc struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "body: %s", w.Body.String())
			assert.Equal(t, tc.wantCode, doc.Code)
		})
	}
}

// Object keys are arbitrary byte strings; the router has to hand the handler the
// decoded key exactly as the client meant it, slashes and escapes included.
func TestRtPxObjectKeyRouting(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name       string
		target     string
		wantBucket string
		wantKey    string
	}{
		{name: "nested key", target: "/backups/velero/default/backup.tar.gz", wantBucket: "backups", wantKey: "velero/default/backup.tar.gz"},
		{name: "percent-encoded spaces", target: "/b/dir/sub%20dir/my%20file.txt", wantBucket: "b", wantKey: "dir/sub dir/my file.txt"},
		{name: "encoded plus stays a plus", target: "/b/key%2Bplus", wantBucket: "b", wantKey: "key+plus"},
		{name: "non-ASCII key", target: "/b/%C3%A4%C3%B6%C3%BC.txt", wantBucket: "b", wantKey: "äöü.txt"},
		{name: "encoded question mark is part of the key", target: "/b/a%3Fb", wantBucket: "b", wantKey: "a?b"},
		{name: "encoded slash becomes a key separator", target: "/b/a%2Fb", wantBucket: "b", wantKey: "a/b"},
		{name: "a key named like a sub-resource is still a key", target: "/b/acl", wantBucket: "b", wantKey: "acl"},
		{name: "key with a trailing slash", target: "/b/prefix/", wantBucket: "b", wantKey: "prefix/"},
		{name: "dot segments that do not normalise", target: "/b/.hidden/..file", wantBucket: "b", wantKey: ".hidden/..file"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			match := RtPxmatch(t, router, req)
			assert.Equal(t, tc.wantBucket, match.Vars["bucket"])
			assert.Equal(t, tc.wantKey, match.Vars["key"])
		})
	}
}

// Defect pin: gorilla/mux cleans the request path before matching, so keys that
// S3 accepts as distinct objects are answered with a 301 to a different key.
// "a//b" and "a/../b" are legal S3 keys; an SDK does not follow the redirect and
// reports PermanentRedirect instead.
func TestRtPxPathNormalisationRedirectsToADifferentKey(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name         string
		target       string
		wantLocation string
	}{
		{name: "double slash in the key", target: "/bucket/a//b", wantLocation: "/bucket/a/b"},
		{name: "dot-dot segment in the key", target: "/bucket/a/../b", wantLocation: "/bucket/b"},
		{name: "single dot segment in the key", target: "/bucket/a/./b", wantLocation: "/bucket/a/b"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.target, nil))

			assert.Equal(t, http.StatusMovedPermanently, w.Code,
				"current behaviour: the key is normalised away instead of being served")
			assert.Equal(t, tc.wantLocation, w.Header().Get("Location"))
			assert.Empty(t, w.Body.String(), "the redirect carries no S3 error document")
		})
	}
}

// Defect pin: a method no route declares is answered by the mux default handler,
// which writes a bare status with no body. AWS answers 405 with an S3 <Error>
// document, and a CORS preflight (OPTIONS) never reaches the CORS middleware
// that would answer it, because middleware only runs once a route has matched.
func TestRtPxUnroutedMethodsBypassTheMiddlewareChain(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name   string
		method string
		target string
	}{
		{name: "CORS preflight for an object", method: http.MethodOptions, target: "/bucket/key"},
		{name: "CORS preflight for a bucket", method: http.MethodOptions, target: "/bucket"},
		{name: "unsupported method", method: http.MethodPatch, target: "/bucket/key"},
		{name: "POST on the service root", method: http.MethodPost, target: "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Empty(t, w.Body.String(), "current behaviour: no S3 error document")
			assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
				"current behaviour: the CORS middleware never sees these requests")
			assert.Empty(t, w.Header().Get("Allow"))
		})
	}
}

// A part upload whose partNumber is not numeric, or that lost its uploadId, does
// not match the multipart routes and reaches the catch-all object route. That is
// the routing fact; what the object handler then does with it is the fix. It used
// to run the plain object PUT, replacing the whole object with the bytes of one
// part and answering 200. Since 568db10 the handler refuses, and since D-27 a PUT
// carrying both parameters is answered 400 InvalidArgument as AWS does - asserted
// in the object package, because only the handler can see it.
func TestRtPxMalformedPartUploadReachesTheObjectHandler(t *testing.T) {
	_, router := RtPxrouter(t, false)

	cases := []struct {
		name   string
		target string
	}{
		{name: "non-numeric part number", target: "/b/k?partNumber=abc&uploadId=u"},
		{name: "negative part number", target: "/b/k?partNumber=-1&uploadId=u"},
		{name: "part number without upload id", target: "/b/k?partNumber=1"},
		{name: "upload id without part number", target: "/b/k?uploadId=u"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, tc.target, nil)
			assert.Contains(t, RtPxhandlerName(t, router, req), "object.(*Handler).Handle",
				"the multipart routes must not match, so the refusal has to come from the object handler")
		})
	}
}

// Health and version answer without a signature - a readiness probe cannot sign
// - while every S3 route stays behind authentication.
func TestRtPxHealthBypassesAuthButS3DoesNot(t *testing.T) {
	_, router := RtPxrouter(t, false)

	for _, target := range []string{"/health", "/version"} {
		t.Run("unauthenticated "+target, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		})
	}

	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/bucket"},
		{http.MethodGet, "/bucket/key"},
		{http.MethodPut, "/bucket/key"},
		{http.MethodDelete, "/bucket/key"},
		{http.MethodPost, "/bucket?delete="},
	} {
		t.Run("unauthenticated "+tc.method+" "+tc.target, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))

			require.Equal(t, http.StatusForbidden, w.Code,
				"an unsigned S3 request must never reach a handler")
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), "<Code>")
		})
	}
}

// With monitoring enabled the metrics middleware wraps every route, including
// the unauthenticated ones; it must not change any response.
func TestRtPxMonitoringMiddlewareIsTransparent(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)
	_, plain := RtPxrouter(t, false)
	_, monitored := RtPxrouter(t, true)

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{name: "health", method: http.MethodGet, target: "/health"},
		{name: "unauthenticated object read", method: http.MethodGet, target: "/bucket/key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := httptest.NewRecorder()
			plain.ServeHTTP(want, httptest.NewRequest(tc.method, tc.target, nil))

			got := httptest.NewRecorder()
			monitored.ServeHTTP(got, httptest.NewRequest(tc.method, tc.target, nil))

			assert.Equal(t, want.Code, got.Code)
			assert.Equal(t, want.Body.String(), got.Body.String())
			assert.Equal(t, want.Header().Get("Content-Type"), got.Header().Get("Content-Type"))
		})
	}
}

// Defect pin: the health and version endpoints are registered before the S3
// routes and match on the path alone, so a bucket named "health" or "version"
// is unreachable through the proxy - a ListObjects on it answers the health
// document, with 200 and no authentication.
func TestRtPxHealthEndpointsShadowSameNamedBuckets(t *testing.T) {
	_, router := RtPxrouter(t, false)

	for _, target := range []string{"/health", "/version", "/health?list-type=2&prefix=a/"} {
		t.Run(target, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"),
				"current behaviour: the bucket listing is shadowed by the probe endpoint")
			assert.NotContains(t, w.Body.String(), "ListBucketResult")
		})
	}

	// Only GET is shadowed; the other verbs still reach the bucket handler.
	req := httptest.NewRequest(http.MethodPut, "/health", nil)
	assert.Contains(t, RtPxhandlerName(t, router, req), "bucket.(*Handler).Handle")
}
