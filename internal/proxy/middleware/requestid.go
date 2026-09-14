package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// RequestIDHeader is the S3 name for the identifier a response states.
const RequestIDHeader = "x-amz-request-id"

// requestIDKey carries the proxy's own request id to whatever logs or answers.
// Unexported and of its own type, like the client identity beside it: an id a
// handler reads is one this package minted, never one a client sent.
type requestIDKey struct{}

// RequestID returns the id this proxy minted for the request, or the empty
// string when it ran outside the middleware.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID mints one id. 16 uppercase hex characters, the shape S3 uses, so
// a client that logs or displays the value sees what it expects.
func NewRequestID() string {
	var raw [8]byte
	// crypto/rand.Read never returns an error since Go 1.24; it terminates the
	// program if the system source is unavailable.
	_, _ = rand.Read(raw[:])
	return strings.ToUpper(hex.EncodeToString(raw[:]))
}

// EnsureRequestID states an id on a response that does not carry one yet and
// returns the request carrying it. It exists for the handlers mux calls outside
// its middleware chain - the method refusal and the CORS preflight, which no
// route matched - so that every answer this proxy gives states an id.
func EnsureRequestID(w http.ResponseWriter, r *http.Request) *http.Request {
	if id := w.Header().Get(RequestIDHeader); id != "" {
		return r
	}
	id := NewRequestID()
	w.Header().Set(RequestIDHeader, id)
	return r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
}

// RequestIDMiddleware states one identifier per request, in the response header
// and in the request context, before anything else can write a status
// (ADR 0008 D12). The error writer reads it back off the header to fill
// <RequestId>, so the document and the header always agree, and the access log
// carries the same value - which is what makes a failure a client saw findable
// in this proxy's own log.
//
// A client-sent x-amz-request-id is overwritten: the value names the proxy's
// handling of this request, and nothing a client supplies can name that.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := NewRequestID()
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}
