package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
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
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	})
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, newCORSConfigurationDocument(output.CORSRules))
}

// handlePutCORS carries the client's CORS document to the backend in full
// (ADR 0007 D5). It used to parse the body into types.CORSConfiguration, which
// has no XML tags, so `<CORSRule>` bound to nothing and PutBucketCors was called
// with an empty rule set - not a valid request, so a perfectly good CORS
// document was answered 500 InternalError.
func (h *CORSHandler) handlePutCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.Logger.WithError(err).WithField("bucket", bucket).Error("Failed to read CORS request body")
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	if len(body) == 0 {
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema")
		return
	}

	var doc corsConfigurationDocument
	if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
		h.Logger.WithError(err).WithField("bucket", bucket).Warn("Refusing a malformed CORS document")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema")
		return
	}

	if _, err := h.S3Backend.PutBucketCors(r.Context(), &s3.PutBucketCorsInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		CORSConfiguration:   doc.corsConfiguration(),
	}); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteCORS handles DELETE bucket CORS requests
func (h *CORSHandler) handleDeleteCORS(w http.ResponseWriter, r *http.Request, bucket string) {
	_, err := h.S3Backend.DeleteBucketCors(r.Context(), &s3.DeleteBucketCorsInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	})
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
