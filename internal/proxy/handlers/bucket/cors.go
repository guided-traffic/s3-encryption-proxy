package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// CORSHandler handles bucket CORS operations
type CORSHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCORSHandler creates a new CORS handler
func NewCORSHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CORSHandler {
	return &CORSHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket CORS operations (?cors)
func (h *CORSHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket CORS operation")

	// Check if S3 client is available (for testing)
	if h.s3Client == nil {
		h.handleMockCORS(w, r, bucket)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetCORS(w, r, bucket)
	case http.MethodPut:
		h.handlePutCORS(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteCORS(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketCORS_"+r.Method)
	}
}

// handleGetCORS handles GET bucket CORS requests
func (h *CORSHandler) handleGetCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	output, err := h.s3Client.GetBucketCors(r.Context(), &s3.GetBucketCorsInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutCORS handles PUT bucket CORS requests
func (h *CORSHandler) handlePutCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	// Read CORS configuration from request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to read CORS request body")
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	if len(body) == 0 {
		h.logger.WithField("bucket", bucket).Error("Empty CORS configuration in request body")
		http.Error(w, "Missing CORS configuration", http.StatusBadRequest)
		return
	}

	// Parse CORS configuration from XML
	var corsConfig types.CORSConfiguration
	if err := xml.Unmarshal(body, &corsConfig); err != nil {
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to parse CORS XML")
		http.Error(w, "Invalid CORS XML format", http.StatusBadRequest)
		return
	}

	// Put bucket CORS configuration
	input := &s3.PutBucketCorsInput{
		Bucket:            aws.String(bucket),
		CORSConfiguration: &corsConfig,
	}

	_, err = h.s3Client.PutBucketCors(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusOK)
}

// handleDeleteCORS handles DELETE bucket CORS requests
func (h *CORSHandler) handleDeleteCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	_, err := h.s3Client.DeleteBucketCors(r.Context(), &s3.DeleteBucketCorsInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusNoContent)
}

// handleMockCORS handles CORS operations when S3 client is not available (testing)
func (h *CORSHandler) handleMockCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	mockCORS := `<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>HEAD</AllowedMethod>
    <AllowedMethod>POST</AllowedMethod>
    <AllowedMethod>DELETE</AllowedMethod>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
    <AllowedHeader>*</AllowedHeader>
  </CORSRule>
</CORSConfiguration>`

	switch r.Method {
	case http.MethodGet:
		h.xmlWriter.WriteRawXML(w, mockCORS)
	case http.MethodPut:
		// Mock successful CORS setting
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		// Mock successful CORS deletion
		w.WriteHeader(http.StatusNoContent)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketCORS_"+r.Method)
	}
}
