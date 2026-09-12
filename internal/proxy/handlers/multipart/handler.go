package multipart

import (
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// Handler handles multipart upload operations
type Handler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
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
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	cfg *config.Config,
) *Handler {
	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, cfg)

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
	h.listHandler = NewListHandler(s3Backend, encryptionMgr, logger, xmlWriter, errorWriter, requestParser)

	return h
}

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
