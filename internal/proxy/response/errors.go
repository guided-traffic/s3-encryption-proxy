package response

import (
	"fmt"
	"html"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// ErrorWriter handles S3 error responses
type ErrorWriter struct {
	logger *logrus.Entry
}

// NewErrorWriter creates a new error response writer
func NewErrorWriter(logger *logrus.Entry) *ErrorWriter {
	return &ErrorWriter{
		logger: logger,
	}
}

// WriteS3Error writes an S3 error response with proper HTTP status codes
func (e *ErrorWriter) WriteS3Error(w http.ResponseWriter, err error, bucket, key string) {
	// Determine the appropriate HTTP status code and error code based on the error type
	var statusCode int
	var errorCode string
	var message string

	// Handle specific S3 error types
	switch err := err.(type) {
	case *types.BucketAlreadyExists:
		statusCode = http.StatusConflict
		errorCode = "BucketAlreadyExists"
		message = "The requested bucket name is not available"
	case *types.BucketAlreadyOwnedByYou:
		statusCode = http.StatusConflict
		errorCode = "BucketAlreadyOwnedByYou"
		message = "Your previous request to create the named bucket succeeded and you already own it"
	case *types.NoSuchBucket:
		statusCode = http.StatusNotFound
		errorCode = "NoSuchBucket"
		message = "The specified bucket does not exist"
	case *types.NoSuchKey:
		statusCode = http.StatusNotFound
		errorCode = "NoSuchKey"
		message = "The specified key does not exist"
	default:
		// For unknown errors, use internal server error
		statusCode = http.StatusInternalServerError
		errorCode = "InternalError"
		message = err.Error()
	}

	// Log the error with appropriate level
	logEntry := e.logger.WithError(err).WithFields(logrus.Fields{
		"bucket":      bucket,
		"key":         key,
		"error_code":  errorCode,
		"status_code": statusCode,
		"message":     message,
	})

	if statusCode >= 500 {
		logEntry.Error("S3 operation failed")
	} else {
		logEntry.Warn("S3 operation failed with client error")
	}

	// Write the error response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	resource := bucket
	if key != "" {
		resource = bucket + "/" + key
	}

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>%s</Code>
    <Message>%s</Message>
    <Resource>%s</Resource>
    <RequestId>%s</RequestId>
</Error>`, html.EscapeString(errorCode), html.EscapeString(message), html.EscapeString(resource), "proxy-request")

	if _, writeErr := w.Write([]byte(response)); writeErr != nil {
		e.logger.WithError(writeErr).Error("Failed to write error response")
	}
}

// WriteGenericError writes a generic error response with custom code and message
func (e *ErrorWriter) WriteGenericError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>%s</Code>
    <Message>%s</Message>
</Error>`, html.EscapeString(code), html.EscapeString(message))

	if _, writeErr := w.Write([]byte(response)); writeErr != nil {
		e.logger.WithError(writeErr).Error("Failed to write generic error response")
	}
}

// WriteNotImplemented writes a "not implemented" response
func (e *ErrorWriter) WriteNotImplemented(w http.ResponseWriter, operation string) {
	// Log to stdout for console tracking
	fmt.Printf("[NOT IMPLEMENTED] Operation '%s' called but not yet implemented\n", operation)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotImplemented</Code>
    <Message>` + operation + ` operation is not yet implemented</Message>
    <Resource>` + operation + `</Resource>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		e.logger.WithError(err).Error("Failed to write not implemented response")
	}
}

// WriteDetailedNotImplemented writes a detailed "not implemented" response
func (e *ErrorWriter) WriteDetailedNotImplemented(w http.ResponseWriter, r *http.Request, operation string) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

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

	// Log detailed information to stdout for console tracking
	fmt.Printf("[NOT IMPLEMENTED] %s (Resource: %s, URL: %s)\n", message, resourcePath, r.URL.String())

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
		e.logger.WithError(err).Error("Failed to write detailed not implemented response")
	}
}
