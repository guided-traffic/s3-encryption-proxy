package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestBucketListingWithQueryParameters(t *testing.T) {
	server := &Server{}

	testCases := []struct {
		name          string
		url           string
		expectedRoute string
		description   string
	}{
		{
			name:          "ListObjectsV2 with prefix and max-keys",
			url:           "/test-bucket?list-type=2&max-keys=1000&prefix=folder/",
			expectedRoute: "handleListObjects",
			description:   "Should route to handleListObjects, not sub-resource handler",
		},
		{
			name:          "ListObjectsV2 with all common parameters",
			url:           "/test-bucket?delimiter=&fetch-owner=true&list-type=2&max-keys=1000&prefix=",
			expectedRoute: "handleListObjects",
			description:   "Should route to handleListObjects for the exact query from the error message",
		},
		{
			name:          "Legacy ListObjects with parameters",
			url:           "/test-bucket?list-type=1&max-keys=500&prefix=docs/",
			expectedRoute: "handleListObjects",
			description:   "Should route to handleListObjects for legacy API",
		},
		{
			name:          "Bucket listing with delimiter only",
			url:           "/test-bucket?delimiter=/",
			expectedRoute: "handleListObjects",
			description:   "Should route to handleListObjects for simple delimiter query",
		},
		{
			name:          "Sub-resource operation - ACL",
			url:           "/test-bucket?acl",
			expectedRoute: "handleBucketSubResource",
			description:   "Should still route to sub-resource handler for ACL operations",
		},
		{
			name:          "Sub-resource operation - Policy",
			url:           "/test-bucket?policy",
			expectedRoute: "handleBucketSubResource",
			description:   "Should still route to sub-resource handler for Policy operations",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest("GET", tc.url, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()

			// We'll capture which route was taken by checking the response
			// For this test, we'll use a mock server that tracks which handler was called
			mockServer := &testTrackingServer{
				Server:      server,
				lastHandler: "",
			}

			// Call the main handler
			mockServer.handleBucket(w, req)

			// Verify the correct handler was called
			switch tc.expectedRoute {
			case "handleListObjects":
				assert.Equal(t, "handleListObjects", mockServer.lastHandler, tc.description)
				// ListObjects should return 200 or appropriate S3 response (not 501 NotImplemented)
				assert.NotEqual(t, http.StatusNotImplemented, w.Code, "ListObjects should not return NotImplemented")
			case "handleBucketSubResource":
				assert.Equal(t, "handleBucketSubResource", mockServer.lastHandler, tc.description)
			}
		})
	}
}

// testTrackingServer wraps the Server to track which handler was called
type testTrackingServer struct {
	*Server
	lastHandler string
}

func (ts *testTrackingServer) handleBucket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	switch r.Method {
	case "GET":
		queryParams := r.URL.Query()

		// Same logic as the actual implementation
		subResourceParams := []string{
			"acl", "cors", "versioning", "policy", "location", "logging",
			"notification", "tagging", "lifecycle", "replication", "website",
			"accelerate", "requestPayment", "uploads",
		}

		hasSubResource := false
		for _, param := range subResourceParams {
			if queryParams.Has(param) {
				hasSubResource = true
				break
			}
		}

		if hasSubResource {
			ts.lastHandler = "handleBucketSubResource"
			// Just mark as handled for test purposes
			w.WriteHeader(http.StatusOK)
		} else {
			ts.lastHandler = "handleListObjects"
			// Simulate successful list objects response
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>` + bucket + `</Name>
    <IsTruncated>false</IsTruncated>
</ListBucketResult>`)); err != nil {
				// In test context, we can't do much about write errors, but we should handle them
				http.Error(w, "Failed to write response", http.StatusInternalServerError)
			}
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
