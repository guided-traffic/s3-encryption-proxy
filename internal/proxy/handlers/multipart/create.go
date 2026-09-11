package multipart

import (
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// CreateHandler handles create multipart upload operations
type CreateHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCreateHandler creates a new create handler
func NewCreateHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CreateHandler {
	return &CreateHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles create multipart upload requests
func (h *CreateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling create multipart upload")

	// The same two helpers the object PUT paths use, so a client-driven upload
	// stores what a single-request PUT of the same headers would (ADR 0007 D3).
	entity, attrs, headerErr := object.ReadUploadHeaders(r)
	if headerErr != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", headerErr.Error())
		return
	}

	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	entity.ApplyToCreateMultipartUpload(input)
	attrs.ApplyToCreateMultipartUpload(input)

	// The object's encryption metadata has to be complete before the backend is
	// asked to open the upload: S3 accepts no metadata at Complete, and attaching
	// it afterwards is the server-side rewrite this format removes (ADR 0003).
	// User metadata travels with it; entries inside the proxy's own namespace are
	// dropped so a client cannot inject its own.
	//
	// Under the exit provider none of that happens: the parts are stored as the
	// client sent them, so there is no data key, no proxy metadata and no
	// session to keep. UploadPart and Complete forward on the same condition.
	var session *orchestration.SegmentedSession
	input.Metadata = h.userMetadata(r)
	if !h.encryptionMgr.IsExitProvider() {
		var sessionErr error
		session, sessionErr = h.encryptionMgr.NewSegmentedSession(key, bucket, h.userMetadata(r))
		if sessionErr != nil {
			h.logger.WithError(sessionErr).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Error("Failed to prepare encryption for the multipart upload")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError",
				"Failed to prepare encryption for the upload")
			return
		}
		input.Metadata = session.Upload.Metadata()
	}

	// Create the multipart upload with S3
	result, err := h.s3Backend.CreateMultipartUpload(r.Context(), input)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload with S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	uploadID := aws.ToString(result.UploadId)

	if session != nil {
		h.encryptionMgr.RegisterSegmentedSession(uploadID, session)
	}

	// Return the CreateMultipartUploadResult
	h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("Sending CreateMultipartUploadResult response to client")

	writeXMLDocument(w, h.logger, initiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	})
}

// userMetadata collects the x-amz-meta-* headers of a request, dropping entries
// that carry the encryption metadata prefix.
func (h *CreateHandler) userMetadata(r *http.Request) map[string]string {
	metadataPrefix := h.encryptionMgr.GetMetadataKeyPrefix()

	metadata := make(map[string]string)
	for name, values := range r.Header {
		if len(values) == 0 || !strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
			continue
		}
		metaKey := strings.ToLower(name[len("x-amz-meta-"):])
		if strings.HasPrefix(metaKey, metadataPrefix) {
			continue
		}
		metadata[metaKey] = values[0]
	}
	return metadata
}
