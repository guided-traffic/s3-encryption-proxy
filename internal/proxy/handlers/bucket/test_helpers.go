package bucket

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
)

// testLogger creates a test logger
func testLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
	return logrus.NewEntry(logger)
}

// testHandler creates a test handler without S3 client for unit tests
func testHandler() *Handler {
	return NewHandler(nil, testLogger(), "s3ep-")
}

// isValidJSON checks if a string is valid JSON
func isValidJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}
