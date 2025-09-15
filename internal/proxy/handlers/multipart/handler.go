package multipart

import (
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// Handler handles multipart upload operations
type Handler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser

	// Sub-handlers
	createHandler   *CreateHandler
	uploadHandler   *UploadHandler
	copyHandler     *CopyHandler
	completeHandler *CompleteHandler
	abortHandler    *AbortHandler
	listHandler     *ListHandler
}

// NewHandler creates a new multipart handler
func NewHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	metadataPrefix string,
) *Handler {
	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, metadataPrefix)

	h := &Handler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}

	// Initialize sub-handlers
	h.createHandler = NewCreateHandler(s3Backend, encryptionMgr, logger, xmlWriter, errorWriter, requestParser)
	h.uploadHandler = NewUploadHandler(s3Backend, encryptionMgr, logger, xmlWriter, errorWriter, requestParser)
	h.copyHandler = NewCopyHandler(s3Backend, encryptionMgr, logger)
	h.completeHandler = NewCompleteHandler(s3Backend, encryptionMgr, logger, xmlWriter, errorWriter, requestParser)
	h.abortHandler = NewAbortHandler(s3Backend, encryptionMgr, logger, xmlWriter, errorWriter, requestParser)
	h.listHandler = NewListHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)

	return h
}

// HandleCreate handles create multipart upload requests (POST /{bucket}/{key}?uploads)
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	h.createHandler.Handle(w, r)
}

// HandleUploadPart handles upload part requests (PUT /{bucket}/{key}?partNumber=X&uploadId=Y)
func (h *Handler) HandleUploadPart(w http.ResponseWriter, r *http.Request) {
	h.uploadHandler.Handle(w, r)
}

// HandleComplete handles complete multipart upload requests (POST /{bucket}/{key}?uploadId=X)
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	h.completeHandler.Handle(w, r)
}

// HandleAbort handles abort multipart upload requests (DELETE /{bucket}/{key}?uploadId=X)
func (h *Handler) HandleAbort(w http.ResponseWriter, r *http.Request) {
	h.abortHandler.Handle(w, r)
}

// HandleListParts handles list parts requests (GET /{bucket}/{key}?uploadId=X)
func (h *Handler) HandleListParts(w http.ResponseWriter, r *http.Request) {
	h.listHandler.HandleListParts(w, r)
}

// HandleListMultipartUploads handles list multipart uploads requests (GET /{bucket}?uploads)
func (h *Handler) HandleListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	h.listHandler.HandleListMultipartUploads(w, r)
}

// GetCreateHandler returns the create handler for direct access
func (h *Handler) GetCreateHandler() *CreateHandler {
	return h.createHandler
}

// GetUploadHandler returns the upload handler for direct access
func (h *Handler) GetUploadHandler() *UploadHandler {
	return h.uploadHandler
}

// GetCopyHandler returns the copy handler for direct access
func (h *Handler) GetCopyHandler() *CopyHandler {
	return h.copyHandler
}

// GetCompleteHandler returns the complete handler for direct access
func (h *Handler) GetCompleteHandler() *CompleteHandler {
	return h.completeHandler
}

// GetAbortHandler returns the abort handler for direct access
func (h *Handler) GetAbortHandler() *AbortHandler {
	return h.abortHandler
}

// GetListHandler returns the list handler for direct access
func (h *Handler) GetListHandler() *ListHandler {
	return h.listHandler
}
