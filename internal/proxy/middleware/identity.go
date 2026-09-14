package middleware

import (
	"context"
	"net/http"
)

// clientIdentityKey carries the authenticated client's access key id down to the
// handlers. It is unexported and of its own type so nothing outside this package
// can set it: a handler that reads an identity must be reading one this package
// authenticated.
type clientIdentityKey struct{}

// WithClientIdentity returns a request carrying the access key id that
// authenticated it.
func WithClientIdentity(r *http.Request, accessKeyID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientIdentityKey{}, accessKeyID))
}

// ClientIdentity returns the access key id that authenticated the request, or
// the empty string on an unauthenticated path such as /health.
func ClientIdentity(ctx context.Context) string {
	id, _ := ctx.Value(clientIdentityKey{}).(string)
	return id
}
