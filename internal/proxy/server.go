package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	s3client "github.com/guided-traffic/s3-encryption-proxy/internal/s3"
	"github.com/sirupsen/logrus"
)

// Server represents the S3 encryption proxy server
type Server struct {
	httpServer    *http.Server
	s3Client      *s3client.Client
	encryptionMgr *encryption.Manager
	config        *config.Config
	logger        *logrus.Entry
}

// NewServer creates a new proxy server instance
func NewServer(cfg *config.Config) (*Server, error) {
	logger := logrus.WithField("component", "proxy-server")

	// Create encryption manager directly from the config
	encryptionMgr, err := encryption.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	// Get active provider for metadata prefix
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Get metadata prefix from provider config
	metadataPrefix := "x-s3ep-" // default
	if prefix, ok := activeProvider.Config["metadata_key_prefix"].(string); ok && prefix != "" {
		metadataPrefix = prefix
	}

	// Create S3 client
	s3Cfg := &s3client.Config{
		Endpoint:       cfg.TargetEndpoint,
		Region:         cfg.Region,
		AccessKeyID:    cfg.AccessKeyID,
		SecretKey:      cfg.SecretKey,
		MetadataPrefix: metadataPrefix,
		DisableSSL:     false, // You might want to make this configurable
		ForcePathStyle: true,  // Common for S3-compatible services
	}

	s3Client, err := s3client.NewClient(s3Cfg, encryptionMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}

	// Create HTTP server with routes
	router := mux.NewRouter()
	server := &Server{
		s3Client:      s3Client,
		encryptionMgr: encryptionMgr,
		config:        cfg,
		logger:        logger,
	}

	// Setup routes
	server.setupRoutes(router)

	httpServer := &http.Server{
		Addr:         cfg.BindAddress,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	server.httpServer = httpServer

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start(ctx context.Context) error {
	// Start HTTP server in a goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if s.config.TLS.Enabled {
			s.logger.WithFields(logrus.Fields{
				"address":   s.config.BindAddress,
				"cert_file": s.config.TLS.CertFile,
				"key_file":  s.config.TLS.KeyFile,
			}).Info("Starting HTTPS server")

			if err := s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		} else {
			s.logger.WithField("address", s.config.BindAddress).Info("Starting HTTP server")
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTP server failed: %w", err)
			}
		}
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-serverErrChan:
		return err
	case <-ctx.Done():
		protocol := "HTTP"
		if s.config.TLS.Enabled {
			protocol = "HTTPS"
		}
		s.logger.WithField("protocol", protocol).Info("Shutting down server")

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.WithError(err).Error("Failed to gracefully shutdown server")
			return err
		}

		s.logger.Info("Server stopped")
		return nil
	}
}

// setupRoutes configures the HTTP routes for the S3 API
func (s *Server) setupRoutes(router *mux.Router) {
	// Health check endpoint
	router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Root endpoint - list buckets
	router.HandleFunc("/", s.handleListBuckets).Methods("GET")

	// Bucket sub-resources (must be defined BEFORE general bucket operations)
	router.HandleFunc("/{bucket}", s.handleBucketACL).Methods("GET", "PUT").Queries("acl", "")
	router.HandleFunc("/{bucket}", s.handleBucketCORS).Methods("GET", "PUT", "DELETE").Queries("cors", "")
	router.HandleFunc("/{bucket}", s.handleBucketVersioning).Methods("GET", "PUT").Queries("versioning", "")
	router.HandleFunc("/{bucket}", s.handleBucketPolicy).Methods("GET", "PUT", "DELETE").Queries("policy", "")
	router.HandleFunc("/{bucket}", s.handleBucketLocation).Methods("GET").Queries("location", "")
	router.HandleFunc("/{bucket}", s.handleBucketLogging).Methods("GET", "PUT").Queries("logging", "")
	router.HandleFunc("/{bucket}", s.handleBucketNotification).Methods("GET", "PUT").Queries("notification", "")
	router.HandleFunc("/{bucket}", s.handleBucketTagging).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	router.HandleFunc("/{bucket}", s.handleBucketLifecycle).Methods("GET", "PUT", "DELETE").Queries("lifecycle", "")
	router.HandleFunc("/{bucket}", s.handleBucketReplication).Methods("GET", "PUT", "DELETE").Queries("replication", "")
	router.HandleFunc("/{bucket}", s.handleBucketWebsite).Methods("GET", "PUT", "DELETE").Queries("website", "")
	router.HandleFunc("/{bucket}", s.handleBucketAccelerate).Methods("GET", "PUT").Queries("accelerate", "")
	router.HandleFunc("/{bucket}", s.handleBucketRequestPayment).Methods("GET", "PUT").Queries("requestPayment", "")

	// Multipart upload operations
	router.HandleFunc("/{bucket}/{key:.*}", s.handleCreateMultipartUpload).Methods("POST").Queries("uploads", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleUploadPart).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleUploadPartCopy).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}").Headers("x-amz-copy-source", "{source}")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleCompleteMultipartUpload).Methods("POST").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleAbortMultipartUpload).Methods("DELETE").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleListParts).Methods("GET").Queries("uploadId", "{uploadId}")
	router.HandleFunc("/{bucket}", s.handleListMultipartUploads).Methods("GET").Queries("uploads", "")

	// Object operations with sub-resources
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectACL).Methods("GET", "PUT").Queries("acl", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectTagging).Methods("GET", "PUT", "DELETE").Queries("tagging", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectLegalHold).Methods("GET", "PUT").Queries("legal-hold", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectRetention).Methods("GET", "PUT").Queries("retention", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObjectTorrent).Methods("GET").Queries("torrent", "")
	router.HandleFunc("/{bucket}/{key:.*}", s.handleSelectObjectContent).Methods("POST").Queries("select", "", "select-type", "2")

	// Delete multiple objects
	router.HandleFunc("/{bucket}", s.handleDeleteObjects).Methods("POST").Queries("delete", "")

	// Bucket operations (general - must be after specific sub-resources)
	router.HandleFunc("/{bucket}", s.handleBucket).Methods("GET", "PUT", "DELETE", "HEAD")
	router.HandleFunc("/{bucket}/", s.handleBucketSlash).Methods("GET", "PUT", "DELETE", "HEAD")

	// Object operations (main)
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObject).Methods("GET", "PUT", "DELETE", "HEAD", "POST")

	// Add middleware
	router.Use(s.loggingMiddleware)
	router.Use(s.corsMiddleware)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.WithError(err).Error("Failed to write health response")
	}
}

// handleListBuckets handles list buckets requests - Pass-through to S3
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling list buckets request - pass-through to S3")

	// Forward request to S3 and proxy response
	output, err := s.s3Client.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		s.handleS3Error(w, err, "Failed to list buckets", "", "")
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Build XML response manually since ListBucketsOutput doesn't have a Body field
	response := `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>` + aws.ToString(output.Owner.ID) + `</ID>
        <DisplayName>` + aws.ToString(output.Owner.DisplayName) + `</DisplayName>
    </Owner>
    <Buckets>`

	for _, bucket := range output.Buckets {
		response += `
        <Bucket>
            <Name>` + aws.ToString(bucket.Name) + `</Name>
            <CreationDate>` + bucket.CreationDate.Format("2006-01-02T15:04:05.000Z") + `</CreationDate>
        </Bucket>`
	}

	response += `
    </Buckets>
</ListAllMyBucketsResult>`

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write list buckets response")
	}
}

// handleListObjects handles bucket listing requests
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling list objects request")

	// Parse query parameters
	queryParams := r.URL.Query()

	// Use ListObjectsV2 by default, but check if legacy ListObjects is requested
	useV2 := queryParams.Get("list-type") != "1"

	if useV2 {
		s.handleListObjectsV2(w, r, bucket, queryParams)
	} else {
		s.handleListObjectsV1(w, r, bucket, queryParams)
	}
}

// handleListObjectsV2 handles ListObjectsV2 requests (recommended S3 API)
func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string, queryParams map[string][]string) {
	// Create S3 ListObjectsV2 input
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}

	// Parse query parameters
	if prefix := getQueryParam(queryParams, "prefix"); prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if delimiter := getQueryParam(queryParams, "delimiter"); delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}
	if maxKeys := getQueryParam(queryParams, "max-keys"); maxKeys != "" {
		if maxKeysInt, err := strconv.ParseInt(maxKeys, 10, 64); err == nil && maxKeysInt > 0 {
			input.MaxKeys = aws.Int32(int32(maxKeysInt))
		}
	}
	if continuationToken := getQueryParam(queryParams, "continuation-token"); continuationToken != "" {
		input.ContinuationToken = aws.String(continuationToken)
	}
	if startAfter := getQueryParam(queryParams, "start-after"); startAfter != "" {
		input.StartAfter = aws.String(startAfter)
	}

	// List objects through our client
	output, err := s.s3Client.ListObjectsV2(r.Context(), input)
	if err != nil {
		s.logger.WithError(err).WithField("bucket", bucket).Error("Failed to list objects")

		statusCode := s.getHTTPStatusFromAWSError(err)
		http.Error(w, fmt.Sprintf("Failed to list objects: %v", err), statusCode)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/xml")

	// Convert response to XML and write
	xmlResponse, err := s.listObjectsV2ToXML(output)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert list objects response to XML")
		http.Error(w, "Failed to format response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(xmlResponse)); err != nil {
		s.logger.WithError(err).Error("Failed to write list objects response")
	}

	s.logger.WithField("bucket", bucket).Debug("Successfully listed objects")
}

// handleListObjectsV1 handles legacy ListObjects requests
func (s *Server) handleListObjectsV1(w http.ResponseWriter, r *http.Request, bucket string, queryParams map[string][]string) {
	// Create S3 ListObjects input
	input := &s3.ListObjectsInput{
		Bucket: aws.String(bucket),
	}

	// Parse query parameters
	if prefix := getQueryParam(queryParams, "prefix"); prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if delimiter := getQueryParam(queryParams, "delimiter"); delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}
	if maxKeys := getQueryParam(queryParams, "max-keys"); maxKeys != "" {
		if maxKeysInt, err := strconv.ParseInt(maxKeys, 10, 64); err == nil && maxKeysInt > 0 {
			input.MaxKeys = aws.Int32(int32(maxKeysInt))
		}
	}
	if marker := getQueryParam(queryParams, "marker"); marker != "" {
		input.Marker = aws.String(marker)
	}

	// List objects through our client
	output, err := s.s3Client.ListObjects(r.Context(), input)
	if err != nil {
		s.logger.WithError(err).WithField("bucket", bucket).Error("Failed to list objects")

		statusCode := s.getHTTPStatusFromAWSError(err)
		http.Error(w, fmt.Sprintf("Failed to list objects: %v", err), statusCode)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/xml")

	// Convert response to XML and write
	xmlResponse, err := s.listObjectsV1ToXML(output)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert list objects response to XML")
		http.Error(w, "Failed to format response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(xmlResponse)); err != nil {
		s.logger.WithError(err).Error("Failed to write list objects response")
	}

	s.logger.WithField("bucket", bucket).Debug("Successfully listed objects")
}

// handleObject handles object operations (GET, PUT, DELETE, HEAD)
func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling object request")

	switch r.Method {
	case "GET":
		s.handleGetObject(w, r, bucket, key)
	case "PUT":
		s.handlePutObject(w, r, bucket, key)
	case "DELETE":
		s.handleDeleteObject(w, r, bucket, key)
	case "HEAD":
		s.handleHeadObject(w, r, bucket, key)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetObject handles GET object requests
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object")

	// Create S3 GetObject input
	input := s.buildGetObjectInput(r, bucket, key)

	// Get the object through our encrypted client
	output, err := s.s3Client.GetObject(r.Context(), input)
	if err != nil {
		s.handleS3Error(w, err, "Failed to get object", bucket, key)
		return
	}
	defer output.Body.Close()

	// Set response headers and write body
	s.setGetObjectResponseHeaders(w, output)
	s.writeObjectBody(w, output.Body, bucket, key)
}

// handleS3Error handles S3 errors and sends appropriate HTTP response
func (s *Server) handleS3Error(w http.ResponseWriter, err error, message, bucket, key string) {
	s.logger.WithError(err).WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Error(message)

	// Convert AWS errors to appropriate HTTP status codes
	statusCode := s.getHTTPStatusFromAWSError(err)
	http.Error(w, fmt.Sprintf("%s: %v", message, err), statusCode)
}

// buildGetObjectInput creates S3 GetObject input from HTTP request
func (s *Server) buildGetObjectInput(r *http.Request, bucket, key string) *s3.GetObjectInput {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Copy relevant headers from request
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		input.Range = aws.String(rangeHeader)
	}
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if t, err := time.Parse(time.RFC1123, ifModifiedSince); err == nil {
			input.IfModifiedSince = aws.Time(t)
		}
	}
	if ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since"); ifUnmodifiedSince != "" {
		if t, err := time.Parse(time.RFC1123, ifUnmodifiedSince); err == nil {
			input.IfUnmodifiedSince = aws.Time(t)
		}
	}

	return input
}

// setGetObjectResponseHeaders sets HTTP response headers for GetObject
func (s *Server) setGetObjectResponseHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	// Set basic content headers
	s.setGetObjectContentHeaders(w, output)

	// Set metadata headers
	s.setGetObjectMetadataHeaders(w, output)

	// Set additional S3 headers
	s.setGetObjectS3Headers(w, output)
}

// setGetObjectContentHeaders sets content-related headers for GetObject
func (s *Server) setGetObjectContentHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	s.setContentHeaders(w, &contentHeadersOutput{
		ContentType:        output.ContentType,
		ContentLength:      output.ContentLength,
		ContentEncoding:    output.ContentEncoding,
		ContentDisposition: output.ContentDisposition,
		ContentLanguage:    output.ContentLanguage,
		CacheControl:       output.CacheControl,
		ETag:               output.ETag,
		LastModified:       output.LastModified,
		Expires:            output.Expires,
	})
}

// setHeadObjectContentHeaders sets content-related headers for HeadObject
func (s *Server) setHeadObjectContentHeaders(w http.ResponseWriter, output *s3.HeadObjectOutput) {
	s.setContentHeaders(w, &contentHeadersOutput{
		ContentType:        output.ContentType,
		ContentLength:      output.ContentLength,
		ContentEncoding:    output.ContentEncoding,
		ContentDisposition: output.ContentDisposition,
		ContentLanguage:    output.ContentLanguage,
		CacheControl:       output.CacheControl,
		ETag:               output.ETag,
		LastModified:       output.LastModified,
		Expires:            output.Expires,
	})
}

// contentHeadersOutput represents common content headers for all output types
type contentHeadersOutput struct {
	ContentType        *string
	ContentLength      *int64
	ContentEncoding    *string
	ContentDisposition *string
	ContentLanguage    *string
	CacheControl       *string
	ETag               *string
	LastModified       *time.Time
	Expires            *time.Time
}

// setContentHeaders sets common content headers
func (s *Server) setContentHeaders(w http.ResponseWriter, output *contentHeadersOutput) {
	if output.ContentType != nil {
		w.Header().Set("Content-Type", aws.ToString(output.ContentType))
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", aws.ToInt64(output.ContentLength)))
	}
	if output.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", aws.ToString(output.ContentEncoding))
	}
	if output.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", aws.ToString(output.ContentDisposition))
	}
	if output.ContentLanguage != nil {
		w.Header().Set("Content-Language", aws.ToString(output.ContentLanguage))
	}
	if output.CacheControl != nil {
		w.Header().Set("Cache-Control", aws.ToString(output.CacheControl))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", aws.ToString(output.ETag))
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}
	if output.Expires != nil {
		w.Header().Set("Expires", output.Expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}
}

// setGetObjectMetadataHeaders sets metadata headers for GetObject
func (s *Server) setGetObjectMetadataHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	for key, value := range output.Metadata {
		w.Header().Set(fmt.Sprintf("x-amz-meta-%s", key), value)
	}
}

// setGetObjectS3Headers sets S3-specific headers for GetObject
func (s *Server) setGetObjectS3Headers(w http.ResponseWriter, output *s3.GetObjectOutput) {
	if output.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", aws.ToString(output.AcceptRanges))
	}
	if len(string(output.StorageClass)) > 0 {
		w.Header().Set("x-amz-storage-class", string(output.StorageClass))
	}
	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", aws.ToString(output.VersionId))
	}
}

// writeObjectBody writes the object body to HTTP response
func (s *Server) writeObjectBody(w http.ResponseWriter, body io.Reader, bucket, key string) {
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, body); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to write object body to response")
	}

	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Successfully retrieved object")
} // handlePutObject handles PUT object requests
func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Putting object")

	// Check if this is a copy object request
	if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
		s.handleCopyObject(w, r)
		return
	}

	// Read the request body into memory
	bodyBytes, err := s.readRequestBody(r, bucket, key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Build S3 PutObject input
	input := s.buildPutObjectInput(r, bucket, key, bodyBytes)

	// Put the object through our encrypted client
	output, err := s.s3Client.PutObject(r.Context(), input)
	if err != nil {
		s.handleS3Error(w, err, "Failed to put object", bucket, key)
		return
	}

	// Set response headers and send success response
	s.setPutObjectResponseHeaders(w, output)
	w.WriteHeader(http.StatusOK)

	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Successfully stored object")
}

// readRequestBody reads and validates the request body
func (s *Server) readRequestBody(r *http.Request, bucket, key string) ([]byte, error) {
	// Note: In production, you might want to stream large files to disk first
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to read request body")
		return nil, err
	}
	return bodyBytes, nil
}

// buildPutObjectInput creates S3 PutObject input from HTTP request
func (s *Server) buildPutObjectInput(r *http.Request, bucket, key string, bodyBytes []byte) *s3.PutObjectInput {
	input := &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(bodyBytes),
		ContentLength: aws.Int64(int64(len(bodyBytes))),
	}

	// Copy relevant headers from request
	s.setPutObjectInputHeaders(r, input)
	s.setPutObjectInputMetadata(r, input)
	s.setPutObjectInputS3Headers(r, input)

	return input
}

// setPutObjectInputHeaders sets standard HTTP headers on PutObject input
func (s *Server) setPutObjectInputHeaders(r *http.Request, input *s3.PutObjectInput) {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		input.ContentType = aws.String(contentType)
	}
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}
	if contentDisposition := r.Header.Get("Content-Disposition"); contentDisposition != "" {
		input.ContentDisposition = aws.String(contentDisposition)
	}
	if contentLanguage := r.Header.Get("Content-Language"); contentLanguage != "" {
		input.ContentLanguage = aws.String(contentLanguage)
	}
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}
	if expires := r.Header.Get("Expires"); expires != "" {
		if t, err := time.Parse(time.RFC1123, expires); err == nil {
			input.Expires = aws.Time(t)
		}
	}
}

// setPutObjectInputMetadata extracts and sets metadata from request headers
func (s *Server) setPutObjectInputMetadata(r *http.Request, input *s3.PutObjectInput) {
	metadata := make(map[string]string)
	for headerName, headerValues := range r.Header {
		if len(headerValues) > 0 && len(headerName) > 11 && headerName[:11] == "X-Amz-Meta-" {
			metaKey := headerName[11:] // Remove "X-Amz-Meta-" prefix
			metadata[metaKey] = headerValues[0]
		}
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}
}

// setPutObjectInputS3Headers sets S3-specific headers on PutObject input
func (s *Server) setPutObjectInputS3Headers(r *http.Request, input *s3.PutObjectInput) {
	if acl := r.Header.Get("x-amz-acl"); acl != "" {
		input.ACL = types.ObjectCannedACL(acl)
	}
	if storageClass := r.Header.Get("x-amz-storage-class"); storageClass != "" {
		input.StorageClass = types.StorageClass(storageClass)
	}
	if tagging := r.Header.Get("x-amz-tagging"); tagging != "" {
		input.Tagging = aws.String(tagging)
	}
}

// setPutObjectResponseHeaders sets HTTP response headers for PutObject
func (s *Server) setPutObjectResponseHeaders(w http.ResponseWriter, output *s3.PutObjectOutput) {
	if output.ETag != nil {
		w.Header().Set("ETag", aws.ToString(output.ETag))
	}
	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", aws.ToString(output.VersionId))
	}
	if output.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", aws.ToString(output.SSECustomerAlgorithm))
	}
	if output.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", aws.ToString(output.SSECustomerKeyMD5))
	}
	if output.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", aws.ToString(output.SSEKMSKeyId))
	}
}

// handleDeleteObject handles DELETE object requests
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Deleting object")

	// Create S3 DeleteObject input
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Handle version ID if provided
	if versionId := r.URL.Query().Get("versionId"); versionId != "" {
		input.VersionId = aws.String(versionId)
	}

	// Delete the object
	output, err := s.s3Client.DeleteObject(r.Context(), input)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to delete object")

		statusCode := s.getHTTPStatusFromAWSError(err)
		http.Error(w, fmt.Sprintf("Failed to delete object: %v", err), statusCode)
		return
	}

	// Set response headers
	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", aws.ToString(output.VersionId))
	}
	if output.DeleteMarker != nil && *output.DeleteMarker {
		w.Header().Set("x-amz-delete-marker", "true")
	}

	w.WriteHeader(http.StatusNoContent)

	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Successfully deleted object")
}

// handleHeadObject handles HEAD object requests
func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object metadata")

	// Create S3 HeadObject input
	input := s.buildHeadObjectInput(r, bucket, key)

	// Get object metadata through our client
	output, err := s.s3Client.HeadObject(r.Context(), input)
	if err != nil {
		s.handleS3Error(w, err, "Failed to get object metadata", bucket, key)
		return
	}

	// Set response headers
	s.setHeadObjectResponseHeaders(w, output)
	w.WriteHeader(http.StatusOK)

	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Successfully retrieved object metadata")
}

// buildHeadObjectInput creates S3 HeadObject input from HTTP request
func (s *Server) buildHeadObjectInput(r *http.Request, bucket, key string) *s3.HeadObjectInput {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Copy relevant headers from request
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if t, err := time.Parse(time.RFC1123, ifModifiedSince); err == nil {
			input.IfModifiedSince = aws.Time(t)
		}
	}
	if ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since"); ifUnmodifiedSince != "" {
		if t, err := time.Parse(time.RFC1123, ifUnmodifiedSince); err == nil {
			input.IfUnmodifiedSince = aws.Time(t)
		}
	}

	return input
}

// setHeadObjectResponseHeaders sets HTTP response headers for HeadObject
func (s *Server) setHeadObjectResponseHeaders(w http.ResponseWriter, output *s3.HeadObjectOutput) {
	// Set basic content headers
	s.setHeadObjectContentHeaders(w, output)

	// Set metadata headers
	s.setHeadObjectMetadataHeaders(w, output)

	// Set additional S3 headers
	s.setHeadObjectS3Headers(w, output)
}

// setHeadObjectMetadataHeaders sets metadata headers for HeadObject
func (s *Server) setHeadObjectMetadataHeaders(w http.ResponseWriter, output *s3.HeadObjectOutput) {
	for key, value := range output.Metadata {
		w.Header().Set(fmt.Sprintf("x-amz-meta-%s", key), value)
	}
}

// setHeadObjectS3Headers sets S3-specific headers for HeadObject
func (s *Server) setHeadObjectS3Headers(w http.ResponseWriter, output *s3.HeadObjectOutput) {
	if output.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", aws.ToString(output.AcceptRanges))
	}
	if len(string(output.StorageClass)) > 0 {
		w.Header().Set("x-amz-storage-class", string(output.StorageClass))
	}
	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", aws.ToString(output.VersionId))
	}
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		s.logger.WithFields(logrus.Fields{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     wrapped.statusCode,
			"duration":   time.Since(start),
			"user_agent": r.UserAgent(),
			"remote_ip":  r.RemoteAddr,
		}).Info("HTTP request")
	})
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getHTTPStatusFromAWSError converts AWS SDK errors to appropriate HTTP status codes
func (s *Server) getHTTPStatusFromAWSError(err error) int {
	if err == nil {
		return http.StatusOK
	}

	// Check for specific AWS error codes
	errStr := err.Error()

	// Common S3 error patterns
	switch {
	case contains(errStr, "NoSuchBucket"):
		return http.StatusNotFound
	case contains(errStr, "NoSuchKey"):
		return http.StatusNotFound
	case contains(errStr, "AccessDenied"):
		return http.StatusForbidden
	case contains(errStr, "InvalidBucketName"):
		return http.StatusBadRequest
	case contains(errStr, "BucketAlreadyExists"):
		return http.StatusConflict
	case contains(errStr, "BucketNotEmpty"):
		return http.StatusConflict
	case contains(errStr, "InvalidArgument"):
		return http.StatusBadRequest
	case contains(errStr, "SignatureDoesNotMatch"):
		return http.StatusForbidden
	case contains(errStr, "RequestTimeout"):
		return http.StatusRequestTimeout
	case contains(errStr, "ServiceUnavailable"):
		return http.StatusServiceUnavailable
	case contains(errStr, "SlowDown"):
		return http.StatusServiceUnavailable
	case contains(errStr, "InternalError"):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) &&
			(s[0:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsMiddle(s, substr)))
}

// getQueryParam safely gets a query parameter value
func getQueryParam(params map[string][]string, key string) string {
	if values, exists := params[key]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// containsMiddle checks if substr is in the middle of s
func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// listObjectsV2ToXML converts S3 ListObjectsV2Output to XML response
func (s *Server) listObjectsV2ToXML(output *s3.ListObjectsV2Output) (string, error) {
	// For now, return a simple XML response
	// In a production system, you'd want to properly marshal this
	result := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>` + aws.ToString(output.Name) + `</Name>
    <Prefix>` + aws.ToString(output.Prefix) + `</Prefix>
    <KeyCount>` + fmt.Sprintf("%d", aws.ToInt32(output.KeyCount)) + `</KeyCount>
    <MaxKeys>` + fmt.Sprintf("%d", aws.ToInt32(output.MaxKeys)) + `</MaxKeys>
    <IsTruncated>` + fmt.Sprintf("%t", aws.ToBool(output.IsTruncated)) + `</IsTruncated>`

	if output.ContinuationToken != nil {
		result += `
    <ContinuationToken>` + aws.ToString(output.ContinuationToken) + `</ContinuationToken>`
	}
	if output.NextContinuationToken != nil {
		result += `
    <NextContinuationToken>` + aws.ToString(output.NextContinuationToken) + `</NextContinuationToken>`
	}

	// Add objects
	for _, obj := range output.Contents {
		result += `
    <Contents>
        <Key>` + aws.ToString(obj.Key) + `</Key>
        <LastModified>` + obj.LastModified.Format(time.RFC3339) + `</LastModified>
        <ETag>` + aws.ToString(obj.ETag) + `</ETag>
        <Size>` + fmt.Sprintf("%d", aws.ToInt64(obj.Size)) + `</Size>
        <StorageClass>` + string(obj.StorageClass) + `</StorageClass>
    </Contents>`
	}

	// Add common prefixes
	for _, prefix := range output.CommonPrefixes {
		result += `
    <CommonPrefixes>
        <Prefix>` + aws.ToString(prefix.Prefix) + `</Prefix>
    </CommonPrefixes>`
	}

	result += `
</ListBucketResult>`

	return result, nil
}

// listObjectsV1ToXML converts S3 ListObjectsOutput to XML response
func (s *Server) listObjectsV1ToXML(output *s3.ListObjectsOutput) (string, error) {
	// For now, return a simple XML response
	// In a production system, you'd want to properly marshal this
	result := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>` + aws.ToString(output.Name) + `</Name>
    <Prefix>` + aws.ToString(output.Prefix) + `</Prefix>
    <Marker>` + aws.ToString(output.Marker) + `</Marker>
    <MaxKeys>` + fmt.Sprintf("%d", aws.ToInt32(output.MaxKeys)) + `</MaxKeys>
    <IsTruncated>` + fmt.Sprintf("%t", aws.ToBool(output.IsTruncated)) + `</IsTruncated>`

	if output.NextMarker != nil {
		result += `
    <NextMarker>` + aws.ToString(output.NextMarker) + `</NextMarker>`
	}

	// Add objects
	for _, obj := range output.Contents {
		result += `
    <Contents>
        <Key>` + aws.ToString(obj.Key) + `</Key>
        <LastModified>` + obj.LastModified.Format(time.RFC3339) + `</LastModified>
        <ETag>` + aws.ToString(obj.ETag) + `</ETag>
        <Size>` + fmt.Sprintf("%d", aws.ToInt64(obj.Size)) + `</Size>
        <StorageClass>` + string(obj.StorageClass) + `</StorageClass>
    </Contents>`
	}

	// Add common prefixes
	for _, prefix := range output.CommonPrefixes {
		result += `
    <CommonPrefixes>
        <Prefix>` + aws.ToString(prefix.Prefix) + `</Prefix>
    </CommonPrefixes>`
	}

	result += `
</ListBucketResult>`

	return result, nil
}
