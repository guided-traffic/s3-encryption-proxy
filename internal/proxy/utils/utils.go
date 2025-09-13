package utils

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	awsHttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// HandleS3Error handles S3 errors with proper logging and response formatting
func HandleS3Error(w http.ResponseWriter, logger logrus.FieldLogger, err error, message, bucket, key string) {
	var statusCode int
	var errorCode string
	var errorMessage string

	// Build resource string
	resource := ""
	if bucket != "" {
		resource = bucket
		if key != "" {
			resource = fmt.Sprintf("%s/%s", bucket, key)
		}
	}

	// Handle different error types
	switch e := err.(type) {
	case *awsHttp.ResponseError:
		statusCode = e.HTTPStatusCode()
		errorCode = "AWSError"
		errorMessage = e.Error()

		// Try to extract more specific error information
		if strings.Contains(errorMessage, "NoSuchBucket") {
			errorCode = "NoSuchBucket"
			errorMessage = "The specified bucket does not exist"
		} else if strings.Contains(errorMessage, "NoSuchKey") {
			errorCode = "NoSuchKey"
			errorMessage = "The specified key does not exist"
		} else if strings.Contains(errorMessage, "AccessDenied") {
			errorCode = "AccessDenied"
			errorMessage = "Access Denied"
		} else if strings.Contains(errorMessage, "BucketAlreadyExists") {
			errorCode = "BucketAlreadyExists"
			errorMessage = "The requested bucket name is not available"
		}

	case *types.NoSuchBucket:
		statusCode = http.StatusNotFound
		errorCode = "NoSuchBucket"
		errorMessage = "The specified bucket does not exist"

	case *types.NoSuchKey:
		statusCode = http.StatusNotFound
		errorCode = "NoSuchKey"
		errorMessage = "The specified key does not exist"

	case *types.BucketAlreadyExists:
		statusCode = http.StatusConflict
		errorCode = "BucketAlreadyExists"
		errorMessage = "The requested bucket name is not available"

	case *types.BucketAlreadyOwnedByYou:
		statusCode = http.StatusConflict
		errorCode = "BucketAlreadyOwnedByYou"
		errorMessage = "Your previous request to create the named bucket succeeded and you already own it"

	default:
		statusCode = http.StatusInternalServerError
		errorCode = "InternalError"
		errorMessage = "We encountered an internal error. Please try again."

		// Check for specific encryption errors
		if strings.Contains(err.Error(), "KEY_MISSING") {
			statusCode = http.StatusBadRequest
			errorCode = "InvalidRequest"
			errorMessage = "Encryption key is missing or invalid"
		} else if strings.Contains(err.Error(), "UNSUPPORTED_PROVIDER") {
			statusCode = http.StatusBadRequest
			errorCode = "InvalidRequest"
			errorMessage = "Unsupported encryption provider"
		}
	}

	// Log the error with context
	logFields := logrus.Fields{
		"error":       err.Error(),
		"message":     message,
		"status_code": statusCode,
		"error_code":  errorCode,
	}
	if bucket != "" {
		logFields["bucket"] = bucket
	}
	if key != "" {
		logFields["key"] = key
	}

	logger.WithFields(logFields).Error("S3 operation failed")

	// Create error response
	errorResponse := S3ErrorResponse{
		Code:     errorCode,
		Message:  errorMessage,
		Resource: resource,
	}

	// Marshal XML response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	xmlData, xmlErr := xml.Marshal(errorResponse)
	if xmlErr != nil {
		logger.WithError(xmlErr).Error("Failed to marshal error response")
		// Fallback to simple error
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InternalError</Code>
    <Message>Internal Server Error</Message>
</Error>`)
		return
	}

	// Write XML header and response
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	w.Write(xmlData)
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
		"url":          r.URL.String(),
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
