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

// ACLHandler handles bucket ACL operations
type ACLHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewACLHandler creates a new ACL handler
func NewACLHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ACLHandler {
	return &ACLHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket ACL operations (?acl)
func (h *ACLHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket ACL operation")

	// Check if S3 client is available (for testing)
	if h.s3Backend == nil {
		h.handleMockACL(w, r, bucket)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetACL(w, r, bucket)
	case http.MethodPut:
		h.handlePutACL(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketACL_"+r.Method)
	}
}

// handleGetACL handles GET bucket ACL requests
func (h *ACLHandler) handleGetACL(w http.ResponseWriter, r *http.Request, bucket string) {
	output, err := h.s3Backend.GetBucketAcl(r.Context(), &s3.GetBucketAclInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutACL handles PUT bucket ACL requests
func (h *ACLHandler) handlePutACL(w http.ResponseWriter, r *http.Request, bucket string) {
	input := &s3.PutBucketAclInput{
		Bucket: aws.String(bucket),
	}

	// Check for canned ACL header
	if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
		// Use canned ACL
		input.ACL = types.BucketCannedACL(cannedACL)
	} else {
		// Parse ACL from request body
		body, err := h.requestParser.ReadBody(r)
		if err != nil {
			h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to read ACL request body")
			h.errorWriter.WriteS3Error(w, err, bucket, "")
			return
		}

		if len(body) > 0 {
			// Parse XML ACL from body
			var acp types.AccessControlPolicy
			if err := xml.Unmarshal(body, &acp); err != nil {
				h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to parse ACL XML")
				http.Error(w, "Invalid ACL XML format", http.StatusBadRequest)
				return
			}
			input.AccessControlPolicy = &acp
		}
	}

	// Execute the PUT operation
	_, err := h.s3Backend.PutBucketAcl(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusOK)
}

// handleMockACL handles ACL operations when S3 client is not available (testing)
func (h *ACLHandler) handleMockACL(w http.ResponseWriter, r *http.Request, _ string) {
	mockACL := `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
  <Owner>
    <ID>mock-owner-id</ID>
    <DisplayName>mock-owner</DisplayName>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee xsi:type="CanonicalUser" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ID>mock-owner-id</ID>
        <DisplayName>mock-owner</DisplayName>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>`

	switch r.Method {
	case http.MethodGet:
		h.xmlWriter.WriteRawXML(w, mockACL)
	case http.MethodPut:
		// Mock successful ACL setting
		w.WriteHeader(http.StatusOK)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketACL_"+r.Method)
	}
}
