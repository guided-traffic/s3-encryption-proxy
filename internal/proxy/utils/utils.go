package utils

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// GetQueryParam safely retrieves a query parameter value
func GetQueryParam(params map[string][]string, key string) string {
	if values, exists := params[key]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// ParseMaxKeys parses the max-keys parameter with validation
func ParseMaxKeys(maxKeysStr string) *int32 {
	if maxKeysStr == "" {
		return nil
	}

	if maxKeys, err := strconv.ParseInt(maxKeysStr, 10, 32); err == nil && maxKeys >= 0 {
		maxKeys32 := int32(maxKeys)
		return &maxKeys32
	}
	return nil
}

// S3ErrorResponse represents an S3 error response
type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId,omitempty"`
}

// HandleS3Error writes an S3 error response for err.
//
// Mapping lives in response.MapError — this is the only mapper in the proxy, so
// the status a client sees does not depend on which handler produced the error.
func HandleS3Error(w http.ResponseWriter, logger logrus.FieldLogger, err error, message, bucket, key string) {
	mapped := response.MapError(err)

	resource := ""
	if bucket != "" {
		resource = bucket
		if key != "" {
			resource = fmt.Sprintf("%s/%s", bucket, key)
		}
	}

	logFields := logrus.Fields{
		"message":     message,
		"status_code": mapped.StatusCode,
		"error_code":  mapped.Code,
	}
	if bucket != "" {
		logFields["bucket"] = bucket
	}
	if key != "" {
		logFields["key"] = key
	}
	entry := logger.WithFields(logFields)
	// Raw SDK text carries backend RequestID and HostID: log only, never respond with it.
	if err != nil {
		entry.WithError(err).Debug("S3 operation error detail")
	}
	if mapped.StatusCode >= http.StatusInternalServerError {
		entry.Error("S3 operation failed")
	} else {
		entry.Warn("S3 operation failed with client error")
	}

	errorResponse := S3ErrorResponse{
		Code:      mapped.Code,
		Message:   mapped.Message,
		Resource:  resource,
		RequestID: "proxy-request",
	}

	// Same document, same order and same indentation as response.ErrorWriter, and
	// marshalled before WriteHeader so a failure cannot leave a truncated body
	// behind a status that is already committed.
	xmlData, xmlErr := xml.MarshalIndent(errorResponse, "", "    ")
	if xmlErr != nil {
		logger.WithError(xmlErr).Error("Failed to marshal error response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(mapped.StatusCode)
	if _, writeErr := w.Write(append([]byte(xml.Header), xmlData...)); writeErr != nil {
		logger.WithError(writeErr).Error("Failed to write error response")
	}
}

// ReadRequestBody reads and returns the request body with error handling
func ReadRequestBody(r *http.Request, logger logrus.FieldLogger, bucket, key string) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to read request body")
		return nil, err
	}
	return body, nil
}

// cleanupTimeout bounds work that must finish after the client is gone.
const cleanupTimeout = 30 * time.Second

// CleanupContext returns a context for backend work that must outlive the
// request: aborting a multipart upload, or attaching encryption metadata to an
// object that is already stored. Using the request context there means a client
// disconnect cancels the cleanup itself, which is exactly when it is needed.
func CleanupContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), cleanupTimeout)
}
