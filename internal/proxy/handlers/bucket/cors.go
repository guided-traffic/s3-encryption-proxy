package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// CORSHandler handles bucket CORS operations
type CORSHandler struct {
	BaseSubResourceHandler
}

// NewCORSHandler creates a new CORS handler
func NewCORSHandler(base BaseSubResourceHandler) *CORSHandler {
	return &CORSHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket CORS operations (?cors)
func (h *CORSHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket CORS operation")

	// Check if S3 client is available (for testing)
	if h.S3Backend == nil {
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
		h.ErrorWriter.WriteNotImplemented(w, "BucketCORS_"+r.Method)
	}
}

// handleGetCORS handles GET bucket CORS requests
func (h *CORSHandler) handleGetCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	output, err := h.S3Backend.GetBucketCors(r.Context(), &s3.GetBucketCorsInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutCORS handles PUT bucket CORS requests
func (h *CORSHandler) handlePutCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	// Read CORS configuration from request body
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.Logger.WithError(err).WithField("bucket", bucket).Error("Failed to read CORS request body")
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	if len(body) == 0 {
		h.Logger.WithField("bucket", bucket).Error("Empty CORS configuration in request body")
		http.Error(w, "Missing CORS configuration", http.StatusBadRequest)
		return
	}

	// Parse CORS configuration from XML
	var corsConfig types.CORSConfiguration
	if err := xml.Unmarshal(body, &corsConfig); err != nil {
		h.Logger.WithError(err).WithField("bucket", bucket).Error("Failed to parse CORS XML")
		http.Error(w, "Invalid CORS XML format", http.StatusBadRequest)
		return
	}

	// Put bucket CORS configuration
	input := &s3.PutBucketCorsInput{
		Bucket:            aws.String(bucket),
		CORSConfiguration: &corsConfig,
	}

	_, err = h.S3Backend.PutBucketCors(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusOK)
}

// handleDeleteCORS handles DELETE bucket CORS requests
func (h *CORSHandler) handleDeleteCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	_, err := h.S3Backend.DeleteBucketCors(r.Context(), &s3.DeleteBucketCorsInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusNoContent)
}

// handleMockCORS handles CORS operations when S3 client is not available (testing)
func (h *CORSHandler) handleMockCORS(w http.ResponseWriter, r *http.Request, _ string) {
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
		h.XMLWriter.WriteRawXML(w, mockCORS)
	case http.MethodPut:
		// Mock successful CORS setting
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		// Mock successful CORS deletion
		w.WriteHeader(http.StatusNoContent)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketCORS_"+r.Method)
	}
}
