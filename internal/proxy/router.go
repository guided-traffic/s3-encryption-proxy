package proxy

import (
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/monitoring"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/bucket"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/health"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/multipart"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/root"
)

// setupRoutes configures the HTTP routes for the S3 API
func (s *Server) setupRoutes(router *mux.Router) {
	// Add monitoring middleware if monitoring is enabled
	if s.config.Monitoring.Enabled {
		router.Use(monitoring.HTTPMiddleware)
	}

	// Initialize handlers
	healthHandler := health.NewHandler(s.logger, s.config.LogHealthRequests)
	healthHandler.SetShutdownStateHandler(s.shutdownStateHandler)
	healthHandler.SetRequestTracker(s.requestStartHandler, s.requestEndHandler)

	// Health and version endpoints - before middleware to avoid authentication
	healthRouter := router.NewRoute().Subrouter()
	healthRouter.HandleFunc("/health", healthHandler.Health).Methods("GET")
	healthRouter.HandleFunc("/version", healthHandler.Version).Methods("GET")

	// S3 API endpoints - protected by S3 authentication
	s3Router := router.NewRoute().Subrouter()

	// Add middleware to S3 router only - order matters: auth first, then tracking, logging, and cors
	s3Router.Use(s.s3AuthMiddleware)
	s3Router.Use(s.requestTrackingMiddleware)
	s3Router.Use(s.loggingMiddleware)
	s3Router.Use(s.corsMiddleware)

	rootHandler := root.NewHandler(s.s3Backend, s.logger)
	bucketHandler := bucket.NewHandler(s.s3Backend, s.logger, s.getMetadataPrefix())
	objectHandler := object.NewHandler(s.s3Backend, s.encryptionMgr, s.config, s.logger)
	multipartHandler := multipart.NewHandler(s.s3Backend, s.encryptionMgr, s.logger, s.getMetadataPrefix())

	// Root endpoint - list buckets
	s3Router.HandleFunc("/", rootHandler.HandleListBuckets).Methods("GET")

	// Bucket sub-resources (must be defined BEFORE general bucket operations)
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetCORSHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("cors", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetPolicyHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("policy", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetLocationHandler().Handle).Methods("GET").Queries("location", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetLoggingHandler().Handle).Methods("GET", "PUT").Queries("logging", "")

	// Migrated handlers - using new bucket handler structure
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetVersioningHandler().Handle).Methods("GET", "PUT").Queries("versioning", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetNotificationHandler().Handle).Methods("GET", "PUT").Queries("notification", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetTaggingHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetLifecycleHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("lifecycle", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetReplicationHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("replication", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetWebsiteHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("website", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetAccelerateHandler().Handle).Methods("GET", "PUT").Queries("accelerate", "")
	s3Router.HandleFunc("/{bucket}", bucketHandler.GetRequestPaymentHandler().Handle).Methods("GET", "PUT").Queries("requestPayment", "")

	// Multipart upload operations - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCreateHandler().Handle).Methods("POST").Queries("uploads", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetUploadHandler().Handle).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCopyHandler().Handle).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}").Headers("x-amz-copy-source", "{source}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCompleteHandler().Handle).Methods("POST").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetAbortHandler().Handle).Methods("DELETE").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetListHandler().HandleListParts).Methods("GET").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket}", multipartHandler.GetListHandler().HandleListMultipartUploads).Methods("GET").Queries("uploads", "")

	// Object operations with sub-resources - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetTaggingHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectLegalHold).Methods("GET", "PUT").Queries("legal-hold", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectRetention).Methods("GET", "PUT").Queries("retention", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleObjectTorrent).Methods("GET").Queries("torrent", "")
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.HandleSelectObjectContent).Methods("POST").Queries("select", "", "select-type", "2")

	// Delete multiple objects - refactored
	s3Router.HandleFunc("/{bucket}", objectHandler.HandleDeleteObjects).Methods("POST").Queries("delete", "")

	// Bucket operations (general - must be after specific sub-resources)
	s3Router.HandleFunc("/{bucket}", bucketHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD")
	s3Router.HandleFunc("/{bucket}/", bucketHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD")

	// Object operations (main) - refactored
	s3Router.HandleFunc("/{bucket}/{key:.*}", objectHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
}
