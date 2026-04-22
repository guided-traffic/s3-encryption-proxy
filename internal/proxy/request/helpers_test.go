package request

import (
	"net/http"
	"net/http/httptest"
)

// newTestRequest builds a minimal *http.Request with the given headers.
func newTestRequest(headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}
