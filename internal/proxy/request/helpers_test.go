package request

import (
	"io"
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

// mustStream unwraps StreamingReader for tests that are not about the up-front
// refusal of a malformed checksum declaration. It takes the call's two results
// directly, which is why it cannot take a *testing.T as well.
func mustStream(src io.Reader, err error) io.Reader {
	if err != nil {
		panic("StreamingReader: " + err.Error())
	}
	return src
}
