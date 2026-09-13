package bucket

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A listing query reaches the listing, and which listing is read from the backend
// call the request turned into — not from a copy of the routing rule.
//
// This file used to hold such a copy: a testTrackingHandler with its own
// fourteen-entry sub-resource list, asserting its own logic. It therefore could
// not catch the bucket-deleting fall-through that made this a security rule in
// the first place, and the next person to change the rule would have changed
// only one of the two.
func TestBktRoutingListingQueriesReachTheListing(t *testing.T) {
	cases := []struct {
		name string
		url  string
		// call is the backend operation the request has to turn into.
		call string
	}{
		{
			name: "ListObjectsV2 with prefix and max-keys",
			url:  "/test-bucket?list-type=2&max-keys=1000&prefix=folder/",
			call: "ListObjectsV2",
		},
		{
			name: "ListObjectsV2 with every common parameter",
			url:  "/test-bucket?delimiter=&fetch-owner=true&list-type=2&max-keys=1000&prefix=",
			call: "ListObjectsV2",
		},
		{
			name: "list-type=1 is the V1 listing",
			url:  "/test-bucket?list-type=1&max-keys=500&prefix=docs/",
			call: "ListObjects",
		},
		{
			name: "no list-type is the V1 listing",
			url:  "/test-bucket?delimiter=/",
			call: "ListObjects",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := BktnewBackend()
			h := BktnewHandlerWith(backend)

			req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, tc.url, nil),
				map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()
			h.Handle(w, req)

			require.NotEqual(t, http.StatusNotImplemented, w.Code,
				"a listing parameter must not be refused as an unknown sub-resource: %s", w.Body.String())
			backend.AssertCalled(t, tc.call, mock.Anything, mock.Anything)

			// And nothing else: a misroute shows up here rather than as a
			// plausible-looking 200.
			for _, other := range []string{"DeleteBucket", "CreateBucket", "DeleteObjects"} {
				backend.AssertNotCalled(t, other, mock.Anything, mock.Anything)
			}
			assert.Equal(t, 1, len(backend.Calls), "exactly one backend operation per request")
		})
	}
}

// A sub-resource has its own route in router.go. Reaching the base handler with
// one means the route did not match — almost always a method it is not
// registered for — and running the base operation for that method is what
// deleted a bucket. It is answered, never performed.
func TestBktRoutingSubResourceNeverRunsTheBaseOperation(t *testing.T) {
	for _, param := range []string{"acl", "policy", "cors", "versioning", "lifecycle"} {
		t.Run(param, func(t *testing.T) {
			backend := BktnewBackend()
			h := BktnewHandlerWith(backend)

			req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/test-bucket?"+param, nil),
				map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()
			h.Handle(w, req)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Equal(t, "MethodNotAllowed", BktparseError(t, w.Body.Bytes()).Code)
			assert.Empty(t, backend.Calls, "no backend operation may run")
		})
	}
}
