package object

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Object retention and legal hold are passthrough (ADR 0007 D4). Both act on the
// ciphertext object, so the proxy has nothing to add to either document. WORM
// here defends against a compromised client credential, not against a compromised
// backend, which can ignore its own lock — SECURITY_ARCHITECTURE.md §3.6 says
// which adversary that is for.
//
// Both used to answer 501, and before that something worse: ?legal-hold read the
// body, discarded it and always sent Status=On, so a client releasing a hold
// applied one; ?retention sent Mode=Governance with no retain-until date whatever
// the body said.

// handleObjectRetention passes GET and PUT /{bucket}/{key}?retention through.
func (h *Handler) handleObjectRetention(w http.ResponseWriter, r *http.Request, bucket, key string) {
	switch r.Method {
	case http.MethodGet:
		output, err := h.s3Backend.GetObjectRetention(r.Context(), &s3.GetObjectRetentionInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: objectVersionID(r),
		})
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}
		h.xmlWriter.WriteS3Document(w, newRetentionDocument(output.Retention))

	case http.MethodPut:
		body, err := h.requestParser.ReadBody(r)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		var doc retentionDocument
		if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema")
			return
		}
		retention, err := doc.retention()
		if err != nil {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
				"RetainUntilDate must be an RFC 3339 timestamp")
			return
		}

		input := &s3.PutObjectRetentionInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: objectVersionID(r),
			Retention: retention,
		}
		// The bypass is the client's decision to make against the backend, and
		// without it a governance-mode shortening is refused there.
		if r.Header.Get("x-amz-bypass-governance-retention") == "true" {
			input.BypassGovernanceRetention = aws.Bool(true)
		}

		if _, err := h.s3Backend.PutObjectRetention(r.Context(), input); err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		h.errorWriter.WriteNotImplemented(w, "ObjectRetention_"+r.Method)
	}
}

// handleObjectLegalHold passes GET and PUT /{bucket}/{key}?legal-hold through.
func (h *Handler) handleObjectLegalHold(w http.ResponseWriter, r *http.Request, bucket, key string) {
	switch r.Method {
	case http.MethodGet:
		output, err := h.s3Backend.GetObjectLegalHold(r.Context(), &s3.GetObjectLegalHoldInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: objectVersionID(r),
		})
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}
		h.xmlWriter.WriteS3Document(w, newLegalHoldDocument(output.LegalHold))

	case http.MethodPut:
		body, err := h.requestParser.ReadBody(r)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		var doc legalHoldDocument
		if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema")
			return
		}

		if _, err := h.s3Backend.PutObjectLegalHold(r.Context(), &s3.PutObjectLegalHoldInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: objectVersionID(r),
			LegalHold: doc.legalHold(),
		}); err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		h.errorWriter.WriteNotImplemented(w, "ObjectLegalHold_"+r.Method)
	}
}
