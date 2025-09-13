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
	healthHandler := health.NewHandler(s.logger)
	healthHandler.SetShutdownStateHandler(s.shutdownStateHandler)
	healthHandler.SetRequestTracker(s.requestStartHandler, s.requestEndHandler)

	rootHandler := root.NewHandler(s.s3Client, s.logger)
	bucketHandler := bucket.NewHandler(s.s3Client, s.logger, s.getMetadataPrefix())
	objectHandler := object.NewHandler(s.s3Client, s.logger, s.getMetadataPrefix())
	multipartHandler := multipart.NewHandler(s.s3Client, s.encryptionMgr, s.logger, s.getMetadataPrefix())

	// Health and version endpoints
	router.HandleFunc("/health", healthHandler.Health).Methods("GET")
	router.HandleFunc("/version", healthHandler.Version).Methods("GET")

	// Root endpoint - list buckets
	router.HandleFunc("/", rootHandler.HandleListBuckets).Methods("GET")

	// Bucket sub-resources (must be defined BEFORE general bucket operations)
	router.HandleFunc("/{bucket}", bucketHandler.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	router.HandleFunc("/{bucket}", bucketHandler.GetCORSHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("cors", "")
	router.HandleFunc("/{bucket}", bucketHandler.GetPolicyHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("policy", "")
	router.HandleFunc("/{bucket}", bucketHandler.GetLocationHandler().Handle).Methods("GET").Queries("location", "")
	router.HandleFunc("/{bucket}", bucketHandler.GetLoggingHandler().Handle).Methods("GET", "PUT").Queries("logging", "")

	// Not yet refactored handlers - temporary
	router.HandleFunc("/{bucket}", s.handleBucketVersioning).Methods("GET", "PUT").Queries("versioning", "")
	router.HandleFunc("/{bucket}", s.handleBucketNotification).Methods("GET", "PUT").Queries("notification", "")
	router.HandleFunc("/{bucket}", s.handleBucketTagging).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	router.HandleFunc("/{bucket}", s.handleBucketLifecycle).Methods("GET", "PUT", "DELETE").Queries("lifecycle", "")
	router.HandleFunc("/{bucket}", s.handleBucketReplication).Methods("GET", "PUT", "DELETE").Queries("replication", "")
	router.HandleFunc("/{bucket}", s.handleBucketWebsite).Methods("GET", "PUT", "DELETE").Queries("website", "")
	router.HandleFunc("/{bucket}", s.handleBucketAccelerate).Methods("GET", "PUT").Queries("accelerate", "")
	router.HandleFunc("/{bucket}", s.handleBucketRequestPayment).Methods("GET", "PUT").Queries("requestPayment", "")

	// Multipart upload operations - refactored
	router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCreateHandler().Handle).Methods("POST").Queries("uploads", "")
	router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetUploadHandler().Handle).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleUploadPartCopy).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}").Headers("x-amz-copy-source", "{source}")
	router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetCompleteHandler().Handle).Methods("POST").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetAbortHandler().Handle).Methods("DELETE").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", multipartHandler.GetListHandler().HandleListParts).Methods("GET").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}", multipartHandler.GetListHandler().HandleListMultipartUploads).Methods("GET").Queries("uploads", "")

	// Object operations with sub-resources - refactored
	router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetACLHandler().Handle).Methods("GET", "PUT").Queries("acl", "")
	router.HandleFunc("/{bucket}/{key:.*}", objectHandler.GetTaggingHandler().Handle).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectLegalHold).Methods("GET", "PUT").Queries("legal-hold", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectRetention).Methods("GET", "PUT").Queries("retention", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectTorrent).Methods("GET").Queries("torrent", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleSelectObjectContent).Methods("POST").Queries("select", "", "select-type", "2")

	// Delete multiple objects - not yet refactored
	router.HandleFunc("/{bucket}", s.handleDeleteObjects).Methods("POST").Queries("delete", "")

	// Bucket operations (general - must be after specific sub-resources)
	router.HandleFunc("/{bucket}", bucketHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD")
	router.HandleFunc("/{bucket}/", bucketHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD")

	// Object operations (main) - refactored
	router.HandleFunc("/{bucket}/{key:.*}", objectHandler.Handle).Methods("GET", "PUT", "DELETE", "HEAD", "POST")

	// Add middleware
	router.Use(s.requestTrackingMiddleware)
	router.Use(s.loggingMiddleware)
	router.Use(s.corsMiddleware)
}
