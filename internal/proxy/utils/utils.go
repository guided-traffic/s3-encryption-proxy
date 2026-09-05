package utils

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"

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
		Code:     mapped.Code,
		Message:  mapped.Message,
		Resource: resource,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(mapped.StatusCode)

	xmlData, xmlErr := xml.Marshal(errorResponse)
	if xmlErr != nil {
		logger.WithError(xmlErr).Error("Failed to marshal error response")
		return
	}
	if _, writeErr := w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`)); writeErr != nil {
		return
	}
	if _, writeErr := w.Write(xmlData); writeErr != nil {
		return
	}
}

// WriteNotImplementedResponse writes a standard "not implemented" response
func WriteNotImplementedResponse(w http.ResponseWriter, logger logrus.FieldLogger, operation string) {
	// Log to console for tracking
	fmt.Printf("[NOT IMPLEMENTED] Operation '%s' called but not yet implemented\n", operation)

	logger.WithField("operation", operation).Warn("Not implemented operation called")

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotImplemented</Code>
    <Message>` + operation + ` operation is not yet implemented</Message>
    <Resource>` + operation + `</Resource>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		logger.WithError(err).Error("Failed to write not implemented response")
	}
}

// WriteDetailedNotImplementedResponse writes a detailed "not implemented" response with method and query parameters
func WriteDetailedNotImplementedResponse(w http.ResponseWriter, logger logrus.FieldLogger, r *http.Request, operation string) {
	// Extract path variables (this would need to be adapted based on router used)
	bucket := ""
	key := ""

	// Add query parameters information
	queryParams := r.URL.Query()
	queryParamsList := make([]string, 0, len(queryParams))
	for param := range queryParams {
		queryParamsList = append(queryParamsList, param)
	}

	// Create detailed message
	var message string
	if len(queryParamsList) > 0 {
		message = fmt.Sprintf("%s operation with method %s and query parameters [%s] is not yet implemented",
			operation, r.Method, fmt.Sprintf("%v", queryParamsList))
	} else {
		message = fmt.Sprintf("%s operation with method %s is not yet implemented", operation, r.Method)
	}

	// Add resource path information
	resourcePath := r.URL.Path
	if bucket != "" {
		resourcePath = fmt.Sprintf("bucket: %s", bucket)
		if key != "" {
			resourcePath = fmt.Sprintf("bucket: %s, key: %s", bucket, key)
		}
	}

	// Log detailed information for console tracking
	fmt.Printf("[NOT IMPLEMENTED] %s (Resource: %s, URL: %s)\n", message, resourcePath, r.URL.String())

	logger.WithFields(logrus.Fields{
		"operation":     operation,
		"method":        r.Method,
		"query_params":  queryParamsList,
		"resource_path": resourcePath,
		"url":           r.URL.String(),
	}).Warn("Detailed not implemented operation called")

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotImplemented</Code>
    <Message>` + message + `</Message>
    <Resource>` + resourcePath + `</Resource>
    <RequestURL>` + r.URL.String() + `</RequestURL>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		logger.WithError(err).Error("Failed to write detailed not implemented response")
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
