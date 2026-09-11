package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// ACLHandler handles bucket ACL operations
type ACLHandler struct {
	BaseSubResourceHandler
}

// NewACLHandler creates a new ACL handler
func NewACLHandler(base BaseSubResourceHandler) *ACLHandler {
	return &ACLHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket ACL operations (?acl)
func (h *ACLHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket ACL operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetACL(w, r, bucket)
	case http.MethodPut:
		h.handlePutACL(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketACL_"+r.Method)
	}
}

// handleGetACL handles GET bucket ACL requests
func (h *ACLHandler) handleGetACL(w http.ResponseWriter, r *http.Request, bucket string) {
	output, err := h.S3Backend.GetBucketAcl(r.Context(), &s3.GetBucketAclInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	})
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, newAccessControlPolicyDocument(output))
}

// handlePutACL carries the client's access-control document to the backend in
// full (ADR 0007 D5). It used to parse the body into types.AccessControlPolicy,
// which has no XML tags, so `<AccessControlList><Grant>` bound to nothing and
// PutBucketAcl was called with an owner and no grants at all - a silent success
// for an ACL nobody set.
func (h *ACLHandler) handlePutACL(w http.ResponseWriter, r *http.Request, bucket string) {
	input := &s3.PutBucketAclInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	// The canned header and the document are alternatives; the header wins where
	// both are present, as at S3.
	if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
		input.ACL = types.BucketCannedACL(cannedACL)
	} else {
		body, err := h.RequestParser.ReadBody(r)
		if err != nil {
			h.Logger.WithError(err).WithField("bucket", bucket).Error("Failed to read ACL request body")
			h.ErrorWriter.WriteS3Error(w, err, bucket, "")
			return
		}

		if len(body) > 0 {
			var doc accessControlPolicyDocument
			if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
				h.Logger.WithError(err).WithField("bucket", bucket).Warn("Refusing a malformed ACL document")
				h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
					"The XML you provided was not well-formed or did not validate against our published schema")
				return
			}
			input.AccessControlPolicy = doc.accessControlPolicy()
		}
	}

	if _, err := h.S3Backend.PutBucketAcl(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}
