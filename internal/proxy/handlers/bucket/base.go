package bucket

import (
	"errors"
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// BaseSubResourceHandler contains the common dependencies shared by all bucket sub-resource handlers.
type BaseSubResourceHandler struct {
	S3Backend     interfaces.S3BackendInterface
	Logger        *logrus.Entry
	XMLWriter     *response.XMLWriter
	ErrorWriter   *response.ErrorWriter
	RequestParser *request.Parser
}

// NewBaseSubResourceHandler creates a new BaseSubResourceHandler with the given dependencies.
func NewBaseSubResourceHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) BaseSubResourceHandler {
	return BaseSubResourceHandler{
		S3Backend:     s3Backend,
		Logger:        logger,
		XMLWriter:     xmlWriter,
		ErrorWriter:   errorWriter,
		RequestParser: requestParser,
	}
}

// readDocument reads a sub-resource document under
// optimizations.max_request_document_size, answering the client itself when it
// cannot and reporting false. Every one of these documents is parsed whole, so
// reading one without a bound is holding whatever the client sends
// (ADR 0011 D5, ADR 0024 D4).
func (h *BaseSubResourceHandler) readDocument(w http.ResponseWriter, r *http.Request, bucket string) ([]byte, bool) {
	body, err := h.RequestParser.ReadDocument(r)
	if err == nil {
		return body, true
	}
	if errors.Is(err, request.ErrBodyTooLarge) {
		h.Logger.WithField("bucket", bucket).
			Warn("Refusing a sub-resource document above optimizations.max_request_document_size")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge",
			"The request document exceeds the maximum size this proxy accepts")
		return nil, false
	}
	h.Logger.WithError(err).WithField("bucket", bucket).Error("Failed to read the request document")
	h.ErrorWriter.WriteS3Error(w, err, bucket, "")
	return nil, false
}
