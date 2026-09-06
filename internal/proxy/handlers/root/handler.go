package root

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// S3 ListBuckets XML response structures
type ListAllMyBucketsResult struct {
	XMLName xml.Name  `xml:"ListAllMyBucketsResult"`
	Owner   S3Owner   `xml:"Owner"`
	Buckets S3Buckets `xml:"Buckets"`
}

type S3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type S3Buckets struct {
	Buckets []S3Bucket `xml:"Bucket"`
}

type S3Bucket struct {
	Name         string    `xml:"Name"`
	CreationDate time.Time `xml:"CreationDate"`
}

// Handler handles root-level S3 operations
type Handler struct {
	s3Backend   interfaces.S3BackendInterface
	logger      logrus.FieldLogger
	errorWriter *response.ErrorWriter
}

// NewHandler creates a new root handler
func NewHandler(s3Backend interfaces.S3BackendInterface, logger logrus.FieldLogger) *Handler {
	return &Handler{
		s3Backend:   s3Backend,
		logger:      logger,
		errorWriter: response.NewErrorWriter(logger.WithField("component", "root-handler")),
	}
}

// HandleListBuckets handles list buckets requests - Pass-through to S3
func (h *Handler) HandleListBuckets(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Handling list buckets request")

	// Use the S3 client to list buckets
	listResult, err := h.s3Backend.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		// Through the mapper, so a backend AccessDenied stays a 403 with an
		// <Error> document instead of becoming an opaque text/plain 500.
		h.errorWriter.WriteS3Error(w, err, "", "")
		return
	}

	// Debug: Log the actual response we got from S3
	bucketCount := 0
	if listResult != nil && listResult.Buckets != nil {
		bucketCount = len(listResult.Buckets)
	}
	h.logger.WithField("bucket_count", bucketCount).Debug("Received ListBuckets response from S3 backend")

	// Convert AWS SDK response to proper S3 XML format
	s3Response := ListAllMyBucketsResult{
		Buckets: S3Buckets{
			Buckets: make([]S3Bucket, 0, len(listResult.Buckets)),
		},
	}

	// Set owner information
	if listResult.Owner != nil {
		if listResult.Owner.ID != nil {
			s3Response.Owner.ID = *listResult.Owner.ID
		}
		if listResult.Owner.DisplayName != nil {
			s3Response.Owner.DisplayName = *listResult.Owner.DisplayName
		}
	}

	// Convert buckets to S3 format
	for _, bucket := range listResult.Buckets {
		s3Bucket := S3Bucket{}
		if bucket.Name != nil {
			s3Bucket.Name = *bucket.Name
		}
		if bucket.CreationDate != nil {
			s3Bucket.CreationDate = *bucket.CreationDate
		}
		s3Response.Buckets.Buckets = append(s3Response.Buckets.Buckets, s3Bucket)
	}

	// Set content type
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Write XML declaration and marshal the response
	if _, err := w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")); err != nil {
		h.logger.WithError(err).Error("Failed to write XML declaration")
		return
	}
	if err := xml.NewEncoder(w).Encode(s3Response); err != nil {
		h.logger.WithError(err).Error("Failed to encode list buckets response")
	}
}
