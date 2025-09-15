package multipart

import (
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// CopyHandler handles upload part copy operations
type CopyHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	errorWriter   *response.ErrorWriter
}

// NewCopyHandler creates a new upload part copy handler
func NewCopyHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
) *CopyHandler {
	return &CopyHandler{
		s3Backend:      s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		errorWriter:   response.NewErrorWriter(logger),
	}
}

// Handle processes upload part copy requests
func (h *CopyHandler) Handle(w http.ResponseWriter, _ *http.Request) {
	h.logger.Debug("Upload part copy operation called")

	// UploadPartCopy is not supported with encryption because:
	// 1. Server-side copy operations work at the S3 storage level
	// 2. Our encryption happens at the proxy level before storage
	// 3. Copying encrypted data would require decrypting source and re-encrypting
	// 4. This breaks the efficiency of server-side copy operations
	h.errorWriter.WriteNotSupportedWithEncryption(w, "UploadPartCopy")
}
