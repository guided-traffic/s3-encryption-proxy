package proxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/monitoring"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/bucket"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/health"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/multipart"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/root"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

// setupRoutes configures the HTTP routes for the S3 API
func (s *Server) setupRoutes(router *mux.Router) {
	// An S3 key is opaque: "a//b", "a/./b" and "a/../b" are three distinct
	// objects, and mux's path cleaning answered a bodiless 301 to a fourth
	// (ADR 0007 D1).
	router.SkipClean(true)

	// A path or a method no route declares is still this proxy's refusal to
	// make, and it is an S3 <Error> document like every other (ADR 0008 D7).
	router.MethodNotAllowedHandler = s.methodNotAllowedHandler(router)

	// First of all, so every answer this router gives carries an id: the S3
	// routes, the probe pair, and the refusals above that no route matched
	// (ADR 0008 D12).
	router.Use(middleware.RequestIDMiddleware)

	// Add monitoring middleware if monitoring is enabled
	if s.config.Monitoring.Enabled {
		router.Use(monitoring.HTTPMiddleware)
	}

	// Initialize handlers
	healthHandler := health.NewHandler(s.logger, s.config.LogHealthRequests, s.build)
	// Late binding on purpose: main creates the server first and installs these
	// handlers afterwards, so the values are still nil here. Copying them would
	// freeze that nil and /health would keep answering 200 while the server
	// drains, which is exactly the signal a readiness probe acts on.
	healthHandler.SetShutdownStateHandler(func() (bool, time.Time) {
		if s.shutdownStateHandler == nil {
			return false, time.Time{}
		}
		return s.shutdownStateHandler()
	})
	healthHandler.SetRequestTracker(
		func() {
			if s.requestStartHandler != nil {
				s.requestStartHandler()
			}
		},
		func() {
			if s.requestEndHandler != nil {
				s.requestEndHandler()
			}
		},
	)

	// Health and version endpoints - before middleware to avoid authentication.
	// The probe is unsigned and carries no parameters; anything else addresses a
	// bucket of that name, which S3 allows, so it falls through to the S3 routes
	// rather than being answered with the probe document (ADR 0014 D11 exempts
	// the probe, not the name).
	healthRouter := router.NewRoute().Subrouter()
	healthRouter.HandleFunc("/health", healthHandler.Health).Methods("GET").MatcherFunc(isProbeRequest)
	healthRouter.HandleFunc("/version", healthHandler.Version).Methods("GET").MatcherFunc(isProbeRequest)

	// S3 API endpoints - protected by S3 authentication
	s3Router := router.NewRoute().Subrouter()

	// Add middleware to S3 router only - order matters: the drain guard first, so
	// a refusal during shutdown costs no signature check and is not counted as
	// work the drain waits for (ADR 0029 D1); then auth, the raw query guard
	// (ADR 0007 D13), tracking, logging, and cors
	s3Router.Use(s.drainGuardMiddleware)
	s3Router.Use(s.s3AuthMiddleware)
	s3Router.Use(s.rawQueryGuardMiddleware)
	s3Router.Use(s.sseCustomerGuardMiddleware)
	s3Router.Use(s.requestTrackingMiddleware)
	s3Router.Use(s.loggingMiddleware)
	s3Router.Use(s.corsMiddleware)

	rootHandler := root.NewHandler(s.s3Backend, s.logger)
	bucketHandler := bucket.NewHandler(s.s3Backend, s.encryptionMgr, s.logger, s.config)
	objectHandler := object.NewHandler(s.s3Backend, s.encryptionMgr, s.config, s.logger)
	multipartHandler := multipart.NewHandler(s.s3Backend, s.encryptionMgr, s.logger, s.config)

	// Root endpoint - list buckets
	s3Router.HandleFunc("/", rootHandler.HandleListBuckets).Methods("GET")

	// Bucket sub-resources (must be defined BEFORE general bucket operations)
	bucketRoute(s3Router, bucketHandler.GetACLHandler().Handle, []string{"GET", "PUT"}, "acl", "")
	bucketRoute(s3Router, bucketHandler.GetCORSHandler().Handle, []string{"GET", "PUT", "DELETE"}, "cors", "")
	bucketRoute(s3Router, bucketHandler.GetPolicyHandler().Handle, []string{"GET", "PUT", "DELETE"}, "policy", "")
	bucketRoute(s3Router, bucketHandler.GetLocationHandler().Handle, []string{"GET"}, "location", "")
	bucketRoute(s3Router, bucketHandler.GetLoggingHandler().Handle, []string{"GET", "PUT"}, "logging", "")

	// Migrated handlers - using new bucket handler structure
	bucketRoute(s3Router, bucketHandler.GetVersioningHandler().Handle, []string{"GET", "PUT"}, "versioning", "")
	bucketRoute(s3Router, bucketHandler.GetNotificationHandler().Handle, []string{"GET", "PUT"}, "notification", "")
	bucketRoute(s3Router, bucketHandler.GetTaggingHandler().Handle, []string{"GET", "PUT", "DELETE"}, "tagging", "")
	bucketRoute(s3Router, bucketHandler.GetLifecycleHandler().Handle, []string{"GET", "PUT", "DELETE"}, "lifecycle", "")
	bucketRoute(s3Router, bucketHandler.GetReplicationHandler().Handle, []string{"GET", "PUT", "DELETE"}, "replication", "")
	bucketRoute(s3Router, bucketHandler.GetWebsiteHandler().Handle, []string{"GET", "PUT", "DELETE"}, "website", "")
	bucketRoute(s3Router, bucketHandler.GetAccelerateHandler().Handle, []string{"GET", "PUT"}, "accelerate", "")
	bucketRoute(s3Router, bucketHandler.GetRequestPaymentHandler().Handle, []string{"GET", "PUT"}, "requestPayment", "")

	// Multipart upload operations - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCreateHandler().Handle).Methods("POST").Queries("uploads", "")
	// UploadPartCopy must be registered before UploadPart: mux matches in
	// registration order, so the header matcher only wins if it comes first.
	// The header value is "" (present, any value) because mux compares the
	// configured value verbatim - "{source}" would be a literal, not a variable.
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCopyHandler().Handle).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}").Headers("x-amz-copy-source", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetUploadHandler().Handle).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCompleteHandler().Handle).Methods("POST").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetAbortHandler().Handle).Methods("DELETE").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetListHandler().HandleListParts).Methods("GET").Queries("uploadId", "{uploadId}")
	bucketRoute(s3Router, multipartHandler.GetListHandler().HandleListMultipartUploads, []string{"GET"}, "uploads", "")

	// Object operations with sub-resources - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetTaggingHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectLegalHold).Methods("GET", "PUT").Queries("legal-hold", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectRetention).Methods("GET", "PUT").Queries("retention", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectTorrent).Methods("GET").Queries("torrent", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleSelectObjectContent).Methods("POST").Queries("select", "", "select-type", "2")

	// Delete multiple objects - refactored
	bucketRoute(s3Router, objectHandler.HandleDeleteObjects, []string{"POST"}, "delete", "")

	// Bucket operations (general - must be after specific sub-resources)
	bucketRoute(s3Router, bucketHandler.Handle, []string{"GET", "PUT", "DELETE", "HEAD"})

	// Object operations (main) - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
}

// bucketRoute registers one bucket route in both forms S3 accepts: "/{bucket}"
// and "/{bucket}/". A trailing slash on a bucket addresses that bucket - there is
// no object with an empty key for it to mean instead - and a client that writes
// one is not asking for something else.
//
// It is a helper rather than sixteen hand-written pairs because a route added
// without its twin is invisible: the request does not fail to route, it reaches
// the general bucket handler, which does not know the sub-resource and answers
// 405. That is how fifteen of them were broken at once. A test walks the router
// and refuses any "/{bucket}" route without a twin.
func bucketRoute(router *mux.Router, handler http.HandlerFunc, methods []string, queries ...string) {
	for _, path := range []string{"/{bucket}", "/{bucket}/"} {
		route := router.HandleFunc(path, handler).Methods(methods...)
		if len(queries) > 0 {
			route.Queries(queries...)
		}
	}
}

// isProbeRequest tells a readiness probe from an S3 request for a bucket that
// happens to be called "health" or "version": a probe is unsigned and carries
// no query at all.
func isProbeRequest(r *http.Request, _ *mux.RouteMatch) bool {
	return r.Header.Get("Authorization") == "" && r.URL.RawQuery == ""
}

// probeMethods are the verbs a router walk drives against a matcher-guarded
// route; kept here so the Allow header of a refusal names the same set.
var refusalMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost,
	http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// methodNotAllowedHandler answers what mux would otherwise answer with a bare
// 405 and an empty body. A CORS preflight reaches it too: no route declares
// OPTIONS, and mux runs a subrouter's middleware only after a route matched, so
// the CORS middleware never sees one. It is answered here instead, unsigned by
// definition and with a response that is the same for every path.
func (s *Server) methodNotAllowedHandler(router *mux.Router) http.Handler {
	cors := middleware.NewCORS(s.logger)
	preflight := cors.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// mux calls this handler outside its middleware chain, so the id that
		// every other answer gets from RequestIDMiddleware is stated here.
		r = middleware.EnsureRequestID(w, r)

		if r.Method == http.MethodOptions {
			preflight.ServeHTTP(w, r)
			return
		}

		if allow := allowedMethods(router, r); len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
		}
		response.NewErrorWriter(s.logger).WriteGenericError(w, http.StatusMethodNotAllowed,
			"MethodNotAllowed", "The specified method is not allowed against this resource.")
	})
}

// allowedMethods asks the router itself which verbs this path does carry.
func allowedMethods(router *mux.Router, r *http.Request) []string {
	var allow []string
	for _, method := range refusalMethods {
		probe := r.Clone(r.Context())
		probe.Method = method

		var match mux.RouteMatch
		if router.Match(probe, &match) && match.MatchErr == nil {
			allow = append(allow, method)
		}
	}
	return allow
}
