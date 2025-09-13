package proxy

import (
	"testing"
)

// DEPRECATED: These tests are deprecated and replaced by the new handler-based tests.
// The functionality tested here has been moved to:
// - internal/proxy/handlers/object/ for object operations
// - internal/proxy/handlers/bucket/ for bucket operations
// - internal/proxy/handlers/multipart/ for multipart operations
//
// This file will be removed after migration is complete.

func TestDeprecated_HandlersMigrated(t *testing.T) {
	t.Skip("These tests have been migrated to the new handler modules")
}
