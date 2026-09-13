package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The id reaches the response and the handler as the same value, and it is the
// proxy's own: a client that sends the header does not get to name this
// proxy's handling of its request (ADR 0008 D12).
func TestMwRequestIDIsStatedAndReachesTheHandler(t *testing.T) {
	var seenByHandler string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenByHandler = RequestID(r.Context())
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	req.Header.Set(RequestIDHeader, "CLIENTSUPPLIED00")

	handler.ServeHTTP(w, req)

	stated := w.Header().Get(RequestIDHeader)
	require.NotEmpty(t, stated)
	assert.Equal(t, stated, seenByHandler, "the header and the context carry one value")
	assert.NotEqual(t, "CLIENTSUPPLIED00", stated)
	assert.Regexp(t, `^[0-9A-F]{16}$`, stated, "the shape S3 uses")
}

// Two requests are two ids. Cheap to assert and the whole point of the value.
func TestMwRequestIDIsUniquePerRequest(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	seen := make(map[string]bool, 512)
	for i := 0; i < 512; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/b/k", nil))

		id := w.Header().Get(RequestIDHeader)
		require.False(t, seen[id], "id %q was stated twice", id)
		seen[id] = true
	}
}

// EnsureRequestID is for the handlers mux calls outside the middleware chain: it
// states an id where there is none and leaves the one already stated alone, so a
// response can never end up carrying two different values.
func TestMwEnsureRequestIDDoesNotRestateAnExistingID(t *testing.T) {
	t.Run("states one where there is none", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := EnsureRequestID(w, httptest.NewRequest(http.MethodPatch, "/b/k", nil))

		id := w.Header().Get(RequestIDHeader)
		require.NotEmpty(t, id)
		assert.Equal(t, id, RequestID(r.Context()))
	})

	t.Run("keeps the one the middleware stated", func(t *testing.T) {
		w := httptest.NewRecorder()
		inner := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			before := w.Header().Get(RequestIDHeader)
			r2 := EnsureRequestID(w, r)
			assert.Equal(t, before, w.Header().Get(RequestIDHeader))
			assert.Equal(t, before, RequestID(r2.Context()))
		}))
		inner.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/b/k", nil))
	})
}

// RequestID on a context that never passed the middleware is empty, which is
// what lets the error writer omit the element rather than invent one.
func TestMwRequestIDIsEmptyOutsideTheMiddleware(t *testing.T) {
	assert.Empty(t, RequestID(httptest.NewRequest(http.MethodGet, "/b/k", nil).Context()))
}
