package response

import (
	"fmt"
	"html"
	"net/http"

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

// WriteS3Error writes an S3 error response, mapping the error through MapError
// so that a backend 404 stays a 404 for the client instead of becoming a 500.
func (e *ErrorWriter) WriteS3Error(w http.ResponseWriter, err error, bucket, key string) {
	mapped := MapError(err)

	resource := bucket
	if key != "" {
		resource = bucket + "/" + key
	}

	logEntry := e.logger.WithFields(logrus.Fields{
		"bucket":      bucket,
		"key":         key,
		"error_code":  mapped.Code,
		"status_code": mapped.StatusCode,
	})
	// The raw SDK text carries backend RequestID, HostID and the operation name.
	// It is useful for debugging and must not reach the client, so it stays here.
	if err != nil {
		logEntry.WithError(err).Debug("S3 operation error detail")
	}
	if mapped.StatusCode >= http.StatusInternalServerError {
		logEntry.Error("S3 operation failed")
	} else {
		logEntry.Warn("S3 operation failed with client error")
	}

	e.writeErrorDocument(w, mapped, resource)
}

// writeErrorDocument renders the S3 <Error> XML document.
func (e *ErrorWriter) writeErrorDocument(w http.ResponseWriter, mapped MappedError, resource string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(mapped.StatusCode)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>%s</Code>
    <Message>%s</Message>
    <Resource>%s</Resource>
    <RequestId>%s</RequestId>
</Error>`, html.EscapeString(mapped.Code), html.EscapeString(mapped.Message), html.EscapeString(resource), "proxy-request")

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

// WriteNotSupportedWithEncryption writes a "not supported with encryption" response
func (e *ErrorWriter) WriteNotSupportedWithEncryption(w http.ResponseWriter, operation string) {
	// Log to stdout for console tracking
	fmt.Printf("[NOT SUPPORTED WITH ENCRYPTION] Operation '%s' is not supported when encryption is enabled\n", operation)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusUnprocessableEntity) // 422 - request cannot be processed due to semantic errors
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotSupportedWithEncryption</Code>
    <Message>` + operation + ` operation is not supported when encryption is enabled. Encrypted objects cannot use S3 server-side copy functionality.</Message>
    <Resource>` + operation + `</Resource>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		e.logger.WithError(err).Error("Failed to write not supported with encryption response")
	}
}
