package utils

import (
	"context"
	"net/http"
	"time"
)

// cleanupTimeout bounds work that must finish after the client is gone.
const cleanupTimeout = 30 * time.Second

// CleanupContext returns a context for backend work that must outlive the
// request: aborting a multipart upload, or attaching encryption metadata to an
// object that is already stored. Using the request context there means a client
// disconnect cancels the cleanup itself, which is exactly when it is needed.
func CleanupContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), cleanupTimeout)
}
