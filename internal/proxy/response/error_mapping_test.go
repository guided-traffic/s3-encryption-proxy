package response

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkError builds the exact error chain aws-sdk-go-v2 hands back for a failed
// operation: *smithy.OperationError -> *awshttp.ResponseError -> the typed error.
// The proxy only ever sees the outermost value, which is why a type switch on it
// matched nothing and every backend error became a 500.
func sdkError(operation string, status int, inner error) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: operation,
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      inner,
			},
			RequestID: "TESTREQUESTID0001",
		},
	}
}

func TestMapError_SDKErrorChains(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{
			name:        "GetObject_NoSuchKey",
			err:         sdkError("GetObject", 404, &types.NoSuchKey{Message: aws.String("The specified key does not exist.")}),
			wantStatus:  http.StatusNotFound,
			wantCode:    "NoSuchKey",
			wantMessage: "The specified key does not exist.",
		},
		{
			name:       "GetObject_NoSuchBucket",
			err:        sdkError("GetObject", 404, &types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")}),
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchBucket",
		},
		{
			name:       "HeadObject_NotFound",
			err:        sdkError("HeadObject", 404, &types.NotFound{}),
			wantStatus: http.StatusNotFound,
			wantCode:   "NotFound",
		},
		{
			name:       "GetObject_AccessDenied",
			err:        sdkError("GetObject", 403, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied."}),
			wantStatus: http.StatusForbidden,
			wantCode:   "AccessDenied",
		},
		{
			name:       "GetObject_PreconditionFailed",
			err:        sdkError("GetObject", 412, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold"}),
			wantStatus: http.StatusPreconditionFailed,
			wantCode:   "PreconditionFailed",
		},
		{
			name:       "GetObject_InvalidRange",
			err:        sdkError("GetObject", 416, &smithy.GenericAPIError{Code: "InvalidRange", Message: "The requested range is not satisfiable"}),
			wantStatus: http.StatusRequestedRangeNotSatisfiable,
			wantCode:   "InvalidRange",
		},
		{
			name:       "UploadPart_NoSuchUpload",
			err:        sdkError("UploadPart", 404, &types.NoSuchUpload{Message: aws.String("The specified upload does not exist.")}),
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchUpload",
		},
		{
			name:       "CompleteMultipartUpload_InvalidPart",
			err:        sdkError("CompleteMultipartUpload", 400, &smithy.GenericAPIError{Code: "InvalidPart", Message: "One or more of the specified parts could not be found"}),
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidPart",
		},
		{
			name:       "CompleteMultipartUpload_EntityTooSmall",
			err:        sdkError("CompleteMultipartUpload", 400, &smithy.GenericAPIError{Code: "EntityTooSmall", Message: "Your proposed upload is smaller than the minimum allowed object size."}),
			wantStatus: http.StatusBadRequest,
			wantCode:   "EntityTooSmall",
		},
		{
			name:       "CreateBucket_BucketAlreadyOwnedByYou",
			err:        sdkError("CreateBucket", 409, &types.BucketAlreadyOwnedByYou{}),
			wantStatus: http.StatusConflict,
			wantCode:   "BucketAlreadyOwnedByYou",
		},
		{
			name:       "CreateBucket_BucketAlreadyExists",
			err:        sdkError("CreateBucket", 409, &types.BucketAlreadyExists{}),
			wantStatus: http.StatusConflict,
			wantCode:   "BucketAlreadyExists",
		},
		{
			name:       "DeleteBucket_BucketNotEmpty",
			err:        sdkError("DeleteBucket", 409, &smithy.GenericAPIError{Code: "BucketNotEmpty", Message: "The bucket you tried to delete is not empty"}),
			wantStatus: http.StatusConflict,
			wantCode:   "BucketNotEmpty",
		},
		{
			name:       "PutObject_SlowDown",
			err:        sdkError("PutObject", 503, &smithy.GenericAPIError{Code: "SlowDown", Message: "Please reduce your request rate."}),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SlowDown",
		},
		{
			name:       "backend_5xx_InternalError",
			err:        sdkError("PutObject", 500, &smithy.GenericAPIError{Code: "InternalError", Message: "We encountered an internal error, please try again."}),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "InternalError",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapError(tc.err)
			assert.Equal(t, tc.wantStatus, got.StatusCode)
			assert.Equal(t, tc.wantCode, got.Code)
			if tc.wantMessage != "" {
				assert.Equal(t, tc.wantMessage, got.Message)
			}
			assert.NotEmpty(t, got.Message, "every mapped error needs a message")
		})
	}
}

// The response must never carry backend identifiers or SDK plumbing text.
func TestMapError_DoesNotLeakBackendDetail(t *testing.T) {
	err := sdkError("GetObject", 404, &types.NoSuchKey{Message: aws.String("The specified key does not exist.")})
	require.Contains(t, err.Error(), "TESTREQUESTID0001", "precondition: the raw SDK text carries the RequestID")

	got := MapError(err)
	for _, leak := range []string{"TESTREQUESTID0001", "RequestID", "HostID", "operation error", "https response error"} {
		assert.NotContains(t, got.Message, leak)
	}
}

// A typed error that never travelled over HTTP still has to get the right status.
func TestMapError_TypedErrorWithoutResponse(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"NoSuchKey":               {&types.NoSuchKey{}, http.StatusNotFound, "NoSuchKey"},
		"NoSuchBucket":            {&types.NoSuchBucket{}, http.StatusNotFound, "NoSuchBucket"},
		"BucketAlreadyOwnedByYou": {&types.BucketAlreadyOwnedByYou{}, http.StatusConflict, "BucketAlreadyOwnedByYou"},
		"NotFound":                {&types.NotFound{}, http.StatusNotFound, "NotFound"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := MapError(tc.err)
			assert.Equal(t, tc.wantStatus, got.StatusCode)
			assert.Equal(t, tc.wantCode, got.Code)
			assert.NotEmpty(t, got.Message)
		})
	}
}

// A response error without a parseable code must still produce its HTTP status.
func TestMapError_ResponseWithoutAPIError(t *testing.T) {
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 404}},
			Err:      errors.New("unparseable body"),
		},
	}
	got := MapError(err)
	assert.Equal(t, http.StatusNotFound, got.StatusCode)
	assert.Equal(t, "NotFound", got.Code)
}

// Internal failures get a fixed generic message: their text can name key
// fingerprints, backend endpoints and file paths.
func TestMapError_InternalErrorsStayGeneric(t *testing.T) {
	cases := map[string]error{
		"plain":             errors.New("aes-gcm: cipher: message authentication failed"),
		"context_canceled":  context.Canceled,
		"context_deadline":  context.DeadlineExceeded,
		"wrapped_io":        fmt.Errorf("failed to read request body: %w", io.ErrUnexpectedEOF),
		"hmac_mismatch":     errors.New("HMAC verification failed for object backup/velero-backup.json.gz"),
		"nil":               nil,
		"operation_no_resp": &smithy.OperationError{ServiceID: "S3", OperationName: "PutObject", Err: context.Canceled},
	}

	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := MapError(err)
			assert.Equal(t, http.StatusInternalServerError, got.StatusCode)
			assert.Equal(t, "InternalError", got.Code)
			assert.Equal(t, genericInternalMessage, got.Message)
			assert.True(t, got.Internal)
			if err != nil {
				assert.NotContains(t, got.Message, err.Error())
			}
		})
	}
}

// Proxy-internal markers keep their deliberate, actionable answer.
func TestMapError_InternalMarkers(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"KEK_MISSING", errors.New("❌ KEK_MISSING: Object 'k' requires KEK fingerprint 'abc'"), http.StatusUnprocessableEntity, "DecryptionError"},
		{"KEK_MISSING_nested", fmt.Errorf("failed to decrypt object data: %w", errors.New("❌ KEK_MISSING: Object 'k'")), http.StatusUnprocessableEntity, "DecryptionError"},
		{"KEY_MISSING", errors.New("encryption: KEY_MISSING"), http.StatusBadRequest, "InvalidRequest"},
		{"UNSUPPORTED_PROVIDER", errors.New("UNSUPPORTED_PROVIDER: vault"), http.StatusBadRequest, "InvalidRequest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapError(tc.err)
			assert.Equal(t, tc.wantStatus, got.StatusCode)
			assert.Equal(t, tc.wantCode, got.Code)
			assert.NotContains(t, got.Message, "fingerprint")
		})
	}
}

// NoSuchBucket carrying the website-configuration message is a distinct code
// for clients.
func TestMapError_WebsiteConfiguration(t *testing.T) {
	got := MapError(&types.NoSuchBucket{Message: aws.String("The specified bucket does not have a website configuration")})
	assert.Equal(t, http.StatusNotFound, got.StatusCode)
	assert.Equal(t, "NoSuchWebsiteConfiguration", got.Code)
}

// MapError must never produce a status net/http will panic on.
func TestMapError_NeverProducesInvalidStatus(t *testing.T) {
	weird := []error{
		&awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 0}},
			Err:      &smithy.GenericAPIError{Code: "WeirdCode", Message: "m"},
		}},
		&smithy.GenericAPIError{Code: "TotallyUnknownCode", Message: "m"},
		sdkError("GetObject", 999, &smithy.GenericAPIError{Code: "X", Message: "m"}),
	}

	for i, err := range weird {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := MapError(err)
			assert.GreaterOrEqual(t, got.StatusCode, 100)
			assert.LessOrEqual(t, got.StatusCode, 599)

			// A real ResponseWriter must accept it without panicking.
			w := httptest.NewRecorder()
			assert.NotPanics(t, func() {
				NewErrorWriter(logrus.NewEntry(discardLogger())).WriteS3Error(w, err, "b", "k")
			})
		})
	}
}

func discardLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// End-to-end through the writer: the XML document a client actually receives.
func TestWriteS3Error_ResponseDocument(t *testing.T) {
	w := httptest.NewRecorder()
	err := sdkError("GetObject", 404, &types.NoSuchKey{Message: aws.String("The specified key does not exist.")})

	NewErrorWriter(logrus.NewEntry(discardLogger())).WriteS3Error(w, err, "velero-backups", "backups/x/velero-backup.json.gz")

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	body := w.Body.String()
	assert.True(t, strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`))
	assert.Contains(t, body, "<Code>NoSuchKey</Code>")
	assert.Contains(t, body, "<Resource>velero-backups/backups/x/velero-backup.json.gz</Resource>")
	assert.NotContains(t, body, "TESTREQUESTID0001")
	assert.NotContains(t, body, "operation error")
}

func TestWriteS3Error_InternalErrorIsOpaque(t *testing.T) {
	w := httptest.NewRecorder()
	secret := "aes key fingerprint 9f8e7d6c at https://internal-minio.svc:9000"

	NewErrorWriter(logrus.NewEntry(discardLogger())).WriteS3Error(w, errors.New(secret), "b", "k")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "9f8e7d6c")
	assert.NotContains(t, w.Body.String(), "internal-minio")
	assert.Contains(t, w.Body.String(), "<Code>InternalError</Code>")
}

func TestWriteS3Error_NilError(t *testing.T) {
	w := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		NewErrorWriter(logrus.NewEntry(discardLogger())).WriteS3Error(w, nil, "b", "k")
	})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Bucket-scoped errors render without a trailing slash in <Resource>.
func TestWriteS3Error_BucketOnlyResource(t *testing.T) {
	w := httptest.NewRecorder()
	NewErrorWriter(logrus.NewEntry(discardLogger())).WriteS3Error(w, sdkError("HeadBucket", 404, &types.NoSuchBucket{}), "mybucket", "")
	assert.Contains(t, w.Body.String(), "<Resource>mybucket</Resource>")
}
