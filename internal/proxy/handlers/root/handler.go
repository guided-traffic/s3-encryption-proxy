package root

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
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
	s3Backend interfaces.S3BackendInterface
	logger   logrus.FieldLogger
}

// NewHandler creates a new root handler
func NewHandler(s3Backend interfaces.S3BackendInterface, logger logrus.FieldLogger) *Handler {
	return &Handler{
		s3Backend: s3Backend,
		logger:   logger,
	}
}

// HandleListBuckets handles list buckets requests - Pass-through to S3
func (h *Handler) HandleListBuckets(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Handling list buckets request")

	// Use the S3 client to list buckets
	response, err := h.s3Backend.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list buckets")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Debug: Log the actual response we got from S3
	bucketCount := 0
	if response != nil && response.Buckets != nil {
		bucketCount = len(response.Buckets)
	}
	h.logger.WithField("bucket_count", bucketCount).Debug("Received ListBuckets response from S3 backend")

	// Convert AWS SDK response to proper S3 XML format
	s3Response := ListAllMyBucketsResult{
		Buckets: S3Buckets{
			Buckets: make([]S3Bucket, 0, len(response.Buckets)),
		},
	}

	// Set owner information
	if response.Owner != nil {
		if response.Owner.ID != nil {
			s3Response.Owner.ID = *response.Owner.ID
		}
		if response.Owner.DisplayName != nil {
			s3Response.Owner.DisplayName = *response.Owner.DisplayName
		}
	}

	// Convert buckets to S3 format
	for _, bucket := range response.Buckets {
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
