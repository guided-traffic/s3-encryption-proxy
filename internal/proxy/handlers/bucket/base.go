package bucket

import (
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
