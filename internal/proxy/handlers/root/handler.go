package root

import (
	"encoding/xml"
	"math"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// S3 ListBuckets XML response structures. The namespace is on the root element:
// a client that validates against the S3 schema needs it, and no document in
// this proxy carried one before.
type ListAllMyBucketsResult struct {
	XMLName           xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner             S3Owner   `xml:"Owner"`
	Buckets           S3Buckets `xml:"Buckets"`
	Prefix            string    `xml:"Prefix,omitempty"`
	ContinuationToken string    `xml:"ContinuationToken,omitempty"`
}

// S3Owner identifies the caller, never the backend account (ADR 0008).
type S3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type S3Buckets struct {
	Buckets []S3Bucket `xml:"Bucket"`
}

// S3Bucket is one <Bucket> element. CreationDate is rendered rather than left
// to encoding/xml for two reasons: a backend reporting none omits the element
// instead of claiming year 0001, and the value carries the three fractional
// digits S3 emits, which Go's time.Time marshalling drops (ADR 0008).
type S3Bucket struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate,omitempty"`
}

// Handler handles root-level S3 operations
type Handler struct {
	s3Backend   interfaces.S3BackendInterface
	logger      logrus.FieldLogger
	xmlWriter   *response.XMLWriter
	errorWriter *response.ErrorWriter
}

// NewHandler creates a new root handler
func NewHandler(s3Backend interfaces.S3BackendInterface, logger logrus.FieldLogger) *Handler {
	entry := logger.WithField("component", "root-handler")
	return &Handler{
		s3Backend:   s3Backend,
		logger:      logger,
		xmlWriter:   response.NewXMLWriter(entry),
		errorWriter: response.NewErrorWriter(entry),
	}
}

// HandleListBuckets handles list buckets requests - Pass-through to S3
func (h *Handler) HandleListBuckets(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Handling list buckets request")

	query := r.URL.Query()
	input := &s3.ListBucketsInput{}
	if v := query.Get("prefix"); v != "" {
		input.Prefix = aws.String(v)
	}
	if v := query.Get("continuation-token"); v != "" {
		input.ContinuationToken = aws.String(v)
	}
	if v := query.Get("bucket-region"); v != "" {
		input.BucketRegion = aws.String(v)
	}
	if v := query.Get("max-buckets"); v != "" {
		n, convErr := strconv.Atoi(v)
		if convErr != nil || n < 0 {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest,
				"InvalidArgument", "max-buckets must be a non-negative integer")
			return
		}
		if n > math.MaxInt32 {
			n = math.MaxInt32
		}
		// #nosec G109,G115 -- n is non-negative and clamped to MaxInt32 above.
		input.MaxBuckets = aws.Int32(int32(n))
	}

	// Use the S3 client to list buckets
	listResult, err := h.s3Backend.ListBuckets(r.Context(), input)
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

	// The owner is the caller, not the backend account whose id the backend
	// returns here (ADR 0008). The proxy has no canonical id for its own
	// clients, so it answers with the access key that authenticated the request.
	if id := middleware.ClientIdentity(r.Context()); id != "" {
		s3Response.Owner.ID = id
		s3Response.Owner.DisplayName = id
	}

	s3Response.Prefix = aws.ToString(listResult.Prefix)
	s3Response.ContinuationToken = aws.ToString(listResult.ContinuationToken)

	// Convert buckets to S3 format
	for _, bucket := range listResult.Buckets {
		s3Bucket := S3Bucket{}
		if bucket.Name != nil {
			s3Bucket.Name = *bucket.Name
		}
		s3Bucket.CreationDate = response.S3Timestamp(bucket.CreationDate)
		s3Response.Buckets.Buckets = append(s3Response.Buckets.Buckets, s3Bucket)
	}

	h.xmlWriter.WriteS3Document(w, s3Response)
}
