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

// WriteS3Error writes an S3 error response
func (e *ErrorWriter) WriteS3Error(w http.ResponseWriter, err error, bucket, key string) {
	// This would need to be implemented with proper S3 error handling
	// For now, a simple implementation
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusInternalServerError)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InternalError</Code>
    <Message>%s</Message>
    <Resource>%s</Resource>
</Error>`, html.EscapeString(err.Error()), html.EscapeString(bucket+"/"+key))

	if _, writeErr := w.Write([]byte(response)); writeErr != nil {
		e.logger.WithError(writeErr).Error("Failed to write error response")
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
