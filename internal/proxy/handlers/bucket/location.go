package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// LocationHandler handles bucket location operations
type LocationHandler struct {
	BaseSubResourceHandler
}

// NewLocationHandler creates a new location handler
func NewLocationHandler(base BaseSubResourceHandler) *LocationHandler {
	return &LocationHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket location operations (?location)
func (h *LocationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket location operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLocation(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketLocation_"+r.Method)
	}
}

// handleGetLocation handles GET bucket location requests
func (h *LocationHandler) handleGetLocation(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket location")

	input := &s3.GetBucketLocationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketLocation(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}
