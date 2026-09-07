package root

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RtPxxmlDeclaration is the prologue every S3 XML response starts with.
const RtPxxmlDeclaration = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// RtPxlistBucketsDoc mirrors what an S3 client parses out of a ListBuckets
// response. The test decodes into its own struct on purpose: asserting against
// the handler's own types would pass even if the wire names changed.
type RtPxlistBucketsDoc struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	Buckets struct {
		Bucket []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Bucket"`
	} `xml:"Buckets"`
}

// RtPxnewHandler builds the handler under test with a quiet logger.
func RtPxnewHandler(t *testing.T) (*Handler, *MockS3Backend) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(RtPxdiscard{})
	logger.SetLevel(logrus.DebugLevel)
	backend := &MockS3Backend{}
	return NewHandler(backend, logger), backend
}

// RtPxdiscard swallows log output so a failing test prints only assertions.
type RtPxdiscard struct{}

func (RtPxdiscard) Write(p []byte) (int, error) { return len(p), nil }

// RtPxdoListBuckets runs one ListBuckets request against the handler.
func RtPxdoListBuckets(t *testing.T, out *s3.ListBucketsOutput, backendErr error) *httptest.ResponseRecorder {
	t.Helper()
	handler, backend := RtPxnewHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	var ret interface{}
	if out != nil {
		ret = out
	}
	backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(ret, backendErr)

	handler.HandleListBuckets(w, req)
	backend.AssertExpectations(t)
	return w
}

// The document a client actually receives: prologue, root element name, owner
// and one <Bucket> per bucket with an RFC3339 creation date.
func TestRtPxListBucketsDocumentShape(t *testing.T) {
	created := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	w := RtPxdoListBuckets(t, &s3.ListBucketsOutput{
		Owner: &types.Owner{
			ID:          aws.String("owner-id-1234"),
			DisplayName: aws.String("test-owner"),
		},
		Buckets: []types.Bucket{
			{Name: aws.String("alpha"), CreationDate: aws.Time(created)},
			{Name: aws.String("beta"), CreationDate: aws.Time(created.Add(time.Hour))},
		},
	}, nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	body := w.Body.String()
	require.True(t, bytes.HasPrefix([]byte(body), []byte(RtPxxmlDeclaration)),
		"an S3 XML response must start with the XML declaration, got %q", body)

	var doc RtPxlistBucketsDoc
	require.NoError(t, xml.Unmarshal([]byte(body), &doc), "body must be well-formed XML: %s", body)

	assert.Equal(t, "ListAllMyBucketsResult", doc.XMLName.Local)
	assert.Equal(t, "owner-id-1234", doc.Owner.ID)
	assert.Equal(t, "test-owner", doc.Owner.DisplayName)

	require.Len(t, doc.Buckets.Bucket, 2)
	assert.Equal(t, "alpha", doc.Buckets.Bucket[0].Name)
	assert.Equal(t, "beta", doc.Buckets.Bucket[1].Name)
	assert.Equal(t, "2021-03-04T05:06:07Z", doc.Buckets.Bucket[0].CreationDate,
		"S3 clients parse the creation date as RFC3339 in UTC")
	assert.Equal(t, "2021-03-04T06:06:07Z", doc.Buckets.Bucket[1].CreationDate)
}

// An account with no buckets: AWS answers 200 with an empty <Buckets> element,
// not 404 and not an empty body.
func TestRtPxListBucketsEmptyAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  *s3.ListBucketsOutput
	}{
		{name: "nil bucket slice", out: &s3.ListBucketsOutput{}},
		{name: "empty bucket slice", out: &s3.ListBucketsOutput{Buckets: []types.Bucket{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := RtPxdoListBuckets(t, tc.out, nil)

			require.Equal(t, http.StatusOK, w.Code)
			var doc RtPxlistBucketsDoc
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
			assert.Empty(t, doc.Buckets.Bucket)
			assert.Empty(t, doc.Owner.ID)
			assert.Contains(t, w.Body.String(), "<Buckets>",
				"the Buckets element must be present even when the account owns none")
		})
	}
}

// A backend that reports an owner with unset fields, and buckets with unset
// fields, must still produce a parseable document rather than panicking.
func TestRtPxListBucketsTolerartesUnsetFields(t *testing.T) {
	w := RtPxdoListBuckets(t, &s3.ListBucketsOutput{
		Owner:   &types.Owner{}, // ID and DisplayName nil
		Buckets: []types.Bucket{{}},
	}, nil)

	require.Equal(t, http.StatusOK, w.Code)
	var doc RtPxlistBucketsDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Empty(t, doc.Owner.ID)
	assert.Empty(t, doc.Owner.DisplayName)
	require.Len(t, doc.Buckets.Bucket, 1)
	assert.Empty(t, doc.Buckets.Bucket[0].Name)
	// Defect note: a bucket without a creation date is serialised as the Go zero
	// time. AWS never omits the date, so this only shows up against a backend
	// that does, but year 0001 is not a value any S3 client expects.
	assert.Equal(t, "0001-01-01T00:00:00Z", doc.Buckets.Bucket[0].CreationDate)
}

// Owner information is optional in the SDK output and must not be invented.
func TestRtPxListBucketsWithoutOwner(t *testing.T) {
	w := RtPxdoListBuckets(t, &s3.ListBucketsOutput{
		Buckets: []types.Bucket{{Name: aws.String("only-bucket"), CreationDate: aws.Time(time.Unix(0, 0).UTC())}},
	}, nil)

	require.Equal(t, http.StatusOK, w.Code)
	var doc RtPxlistBucketsDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Empty(t, doc.Owner.ID)
	require.Len(t, doc.Buckets.Bucket, 1)
	assert.Equal(t, "only-bucket", doc.Buckets.Bucket[0].Name)
	assert.Equal(t, "1970-01-01T00:00:00Z", doc.Buckets.Bucket[0].CreationDate)
}

// RtPxfailingWriter fails writes from the failAfter-th call on, which is what a
// client that hangs up mid-response looks like to the handler.
type RtPxfailingWriter struct {
	header    http.Header
	status    int
	writes    int
	failAfter int
	body      bytes.Buffer
}

func (f *RtPxfailingWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}

func (f *RtPxfailingWriter) WriteHeader(status int) { f.status = status }

func (f *RtPxfailingWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("connection reset by peer")
	}
	return f.body.Write(p)
}

// A client disconnecting mid-response must not panic the handler, whether it
// goes away before the XML declaration or between declaration and body.
func TestRtPxListBucketsClientDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failAfter int
		wantBody  string
	}{
		{name: "fails on the XML declaration", failAfter: 0, wantBody: ""},
		{name: "fails while encoding the document", failAfter: 1, wantBody: RtPxxmlDeclaration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, backend := RtPxnewHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := &RtPxfailingWriter{failAfter: tc.failAfter}

			backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).
				Return(&s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("b"), CreationDate: aws.Time(time.Unix(1, 0).UTC())}},
				}, nil)

			require.NotPanics(t, func() { handler.HandleListBuckets(w, req) })

			assert.Equal(t, http.StatusOK, w.status)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Equal(t, tc.wantBody, w.body.String())
			backend.AssertExpectations(t)
		})
	}
}

// Every backend failure has to reach the client as an S3 <Error> document with
// the backend's own status, and never as a bare 500 or as leaked SDK text.
func TestRtPxListBucketsBackendErrors(t *testing.T) {
	sdkErr := func(status int, inner error) error {
		return &smithy.OperationError{
			ServiceID:     "S3",
			OperationName: "ListBuckets",
			Err: &awshttp.ResponseError{
				ResponseError: &smithyhttp.ResponseError{
					Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
					Err:      inner,
				},
				RequestID: "RTPXREQUESTID0001",
			},
		}
	}

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid credentials",
			err:        sdkErr(http.StatusForbidden, &smithy.GenericAPIError{Code: "InvalidAccessKeyId", Message: "The AWS Access Key Id you provided does not exist in our records."}),
			wantStatus: http.StatusForbidden,
			wantCode:   "InvalidAccessKeyId",
		},
		{
			name:       "backend unreachable",
			err:        errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "InternalError",
		},
		{
			name:       "backend answers 503",
			err:        sdkErr(http.StatusServiceUnavailable, &smithy.GenericAPIError{Code: "ServiceUnavailable", Message: "Reduce your request rate."}),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "ServiceUnavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := RtPxdoListBuckets(t, nil, tc.err)

			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

			var doc struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
				Message string   `xml:"Message"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "error body must be XML: %s", w.Body.String())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.NotEmpty(t, doc.Message)
			assert.NotContains(t, w.Body.String(), "RTPXREQUESTID0001",
				"the backend request id must not be echoed to the client")
			assert.NotContains(t, w.Body.String(), "10.0.0.1",
				"backend addresses must not leak into a client-visible error")
		})
	}
}

// The handler must not answer a request its backend never saw: the request
// context is what carries client cancellation into the SDK call.
func TestRtPxListBucketsPassesRequestContext(t *testing.T) {
	handler, backend := RtPxnewHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).
		Return(&s3.ListBucketsOutput{}, nil).Once()

	handler.HandleListBuckets(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	backend.AssertExpectations(t)
	backend.AssertNumberOfCalls(t, "ListBuckets", 1)
}

// NewHandler must produce a handler that is usable as-is; a nil error writer
// would turn the first backend failure into a panic instead of a 403.
func TestRtPxNewHandlerIsUsableImmediately(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(RtPxdiscard{})
	backend := &MockS3Backend{}

	handler := NewHandler(backend, logger.WithField("test", "RtPx"))
	require.NotNil(t, handler)
	require.NotNil(t, handler.errorWriter)
	require.NotNil(t, handler.s3Backend)
	require.NotNil(t, handler.logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(nil, errors.New("boom"))

	require.NotPanics(t, func() { handler.HandleListBuckets(w, req) })
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "<Code>InternalError</Code>")
}
