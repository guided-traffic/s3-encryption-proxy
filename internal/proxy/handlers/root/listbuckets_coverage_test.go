package root

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// RtPxxmlDeclaration is the prologue every S3 XML response starts with.
const RtPxxmlDeclaration = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// RtPxrootElement is the opening tag a client sees. The namespace belongs on the
// root element: a client validating against the S3 schema needs it, and the
// document carried none before the listing rewrite.
const RtPxrootElement = `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`

// RtPxbackendOwnerID and RtPxbackendOwnerName are what the backend reports as
// the owner of the account the proxy itself authenticates with. Neither may ever
// reach a client: the proxy answers with the caller, not with its own S3 account.
const (
	RtPxbackendOwnerID   = "backend-account-owner-id-1234"
	RtPxbackendOwnerName = "backend-account-display-name"
)

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
	Prefix            string `xml:"Prefix"`
	ContinuationToken string `xml:"ContinuationToken"`
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

// RtPxrequest describes one ListBuckets round trip against the handler.
type RtPxrequest struct {
	// query is appended to "/" verbatim, including the leading "?".
	query string
	// identity is the authenticated access key the auth middleware would have
	// put into the request context. Empty leaves the context unauthenticated.
	identity string
	// out and backendErr are what the mocked backend answers.
	out        *s3.ListBucketsOutput
	backendErr error
	// noBackend marks the requests the handler must refuse before it ever calls
	// the backend.
	noBackend bool
}

// RtPxcall is the result of one round trip: the recorded response plus the input
// the backend was actually called with (nil when the handler refused earlier).
type RtPxcall struct {
	rec   *httptest.ResponseRecorder
	input *s3.ListBucketsInput
}

func (c RtPxcall) body() string { return c.rec.Body.String() }

// RtPxlistBuckets runs one ListBuckets request and captures the input the
// handler built, which is the only place the forwarded query parameters are
// visible - they never appear in the response document.
func RtPxlistBuckets(t *testing.T, rq RtPxrequest) RtPxcall {
	t.Helper()
	handler, backend := RtPxnewHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/"+rq.query, nil)
	if rq.identity != "" {
		req = middleware.WithClientIdentity(req, rq.identity)
	}
	w := httptest.NewRecorder()

	call := RtPxcall{rec: w}
	if !rq.noBackend {
		var ret interface{}
		if rq.out != nil {
			ret = rq.out
		}
		backend.On("ListBuckets", req.Context(), mock.Anything).
			Run(func(args mock.Arguments) {
				call.input = args.Get(1).(*s3.ListBucketsInput)
			}).
			Return(ret, rq.backendErr).Once()
	}

	handler.HandleListBuckets(w, req)

	backend.AssertExpectations(t)
	if rq.noBackend {
		backend.AssertNotCalled(t, "ListBuckets", mock.Anything, mock.Anything)
	}
	return call
}

// RtPxdoListBuckets runs one plain, unauthenticated ListBuckets request.
func RtPxdoListBuckets(t *testing.T, out *s3.ListBucketsOutput, backendErr error) *httptest.ResponseRecorder {
	t.Helper()
	return RtPxlistBuckets(t, RtPxrequest{out: out, backendErr: backendErr}).rec
}

// The document a client actually receives, asserted on the raw body: an SDK
// round trip hides the declaration, the root element and the namespace, which is
// exactly what this handler has to get right.
func TestRtPxListBucketsDocumentShape(t *testing.T) {
	created := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	call := RtPxlistBuckets(t, RtPxrequest{
		identity: "AKIACALLER0001",
		out: &s3.ListBucketsOutput{
			Owner: &types.Owner{
				ID:          aws.String(RtPxbackendOwnerID),
				DisplayName: aws.String(RtPxbackendOwnerName),
			},
			Buckets: []types.Bucket{
				{Name: aws.String("alpha"), CreationDate: aws.Time(created)},
				{Name: aws.String("beta"), CreationDate: aws.Time(created.Add(time.Hour))},
			},
		},
	})

	require.Equal(t, http.StatusOK, call.rec.Code)
	assert.Equal(t, "application/xml", call.rec.Header().Get("Content-Type"))

	body := call.body()
	require.True(t, strings.HasPrefix(body, RtPxxmlDeclaration),
		"an S3 XML response must start with the XML declaration, got %q", body)
	assert.Equal(t, 1, strings.Count(body, "<?xml"),
		"the declaration is written exactly once, not once per writer in the chain: %s", body)
	assert.Contains(t, body, RtPxrootElement,
		"the namespace belongs on the root element: %s", body)

	// The caller owns the listing. The backend's own account owner is dropped:
	// it identifies the proxy's S3 credentials, which no client may learn.
	assert.Contains(t, body, "<Owner><ID>AKIACALLER0001</ID><DisplayName>AKIACALLER0001</DisplayName></Owner>")
	assert.NotContains(t, body, RtPxbackendOwnerID,
		"the backend account owner id must never reach a client: %s", body)
	assert.NotContains(t, body, RtPxbackendOwnerName,
		"the backend account display name must never reach a client: %s", body)

	var doc RtPxlistBucketsDoc
	require.NoError(t, xml.Unmarshal([]byte(body), &doc), "body must be well-formed XML: %s", body)

	assert.Equal(t, "ListAllMyBucketsResult", doc.XMLName.Local)
	assert.Equal(t, "http://s3.amazonaws.com/doc/2006-03-01/", doc.XMLName.Space)

	require.Len(t, doc.Buckets.Bucket, 2)
	assert.Equal(t, "alpha", doc.Buckets.Bucket[0].Name)
	assert.Equal(t, "beta", doc.Buckets.Bucket[1].Name)
	assert.Equal(t, "2021-03-04T05:06:07.000Z", doc.Buckets.Bucket[0].CreationDate,
		"the three fractional digits are what S3 emits, and what the object listing already emitted")
	assert.Equal(t, "2021-03-04T06:06:07.000Z", doc.Buckets.Bucket[1].CreationDate)
}

// The Owner is the authenticated caller and nothing else (ADR 0008). Without an
// identity in the context it stays empty rather than falling back to the backend
// account, which is the answer the old handler gave.
func TestRtPxListBucketsOwnerIsTheCaller(t *testing.T) {
	backendOwner := &types.Owner{
		ID:          aws.String(RtPxbackendOwnerID),
		DisplayName: aws.String(RtPxbackendOwnerName),
	}

	for _, tc := range []struct {
		name      string
		identity  string
		owner     *types.Owner
		wantOwner string
	}{
		{
			name:      "authenticated caller owns the listing",
			identity:  "username0",
			owner:     backendOwner,
			wantOwner: "<Owner><ID>username0</ID><DisplayName>username0</DisplayName></Owner>",
		},
		{
			name:      "no identity leaves the owner empty",
			identity:  "",
			owner:     backendOwner,
			wantOwner: "<Owner><ID></ID><DisplayName></DisplayName></Owner>",
		},
		{
			name:      "backend without an owner changes nothing",
			identity:  "username0",
			owner:     nil,
			wantOwner: "<Owner><ID>username0</ID><DisplayName>username0</DisplayName></Owner>",
		},
		{
			name:      "backend owner with unset fields changes nothing",
			identity:  "username0",
			owner:     &types.Owner{},
			wantOwner: "<Owner><ID>username0</ID><DisplayName>username0</DisplayName></Owner>",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := RtPxlistBuckets(t, RtPxrequest{
				identity: tc.identity,
				out: &s3.ListBucketsOutput{
					Owner:   tc.owner,
					Buckets: []types.Bucket{{Name: aws.String("only-bucket"), CreationDate: aws.Time(time.Unix(0, 0).UTC())}},
				},
			})

			require.Equal(t, http.StatusOK, call.rec.Code)
			assert.Contains(t, call.body(), tc.wantOwner)
			assert.NotContains(t, call.body(), RtPxbackendOwnerID)
			assert.NotContains(t, call.body(), RtPxbackendOwnerName)
		})
	}
}

// The listing query parameters are pagination and filtering: dropping one turns
// a paged listing into an endless loop, so each has to reach ListBucketsInput.
func TestRtPxListBucketsForwardsQueryParameters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  s3.ListBucketsInput
	}{
		{
			name:  "no query sends an empty input",
			query: "",
			want:  s3.ListBucketsInput{},
		},
		{
			name:  "prefix",
			query: "?prefix=logs%2F",
			want:  s3.ListBucketsInput{Prefix: aws.String("logs/")},
		},
		{
			name:  "continuation token survives its padding",
			query: "?continuation-token=dG9rZW4%3D",
			want:  s3.ListBucketsInput{ContinuationToken: aws.String("dG9rZW4=")},
		},
		{
			name:  "bucket region",
			query: "?bucket-region=eu-central-1",
			want:  s3.ListBucketsInput{BucketRegion: aws.String("eu-central-1")},
		},
		{
			name:  "max buckets",
			query: "?max-buckets=42",
			want:  s3.ListBucketsInput{MaxBuckets: aws.Int32(42)},
		},
		{
			name:  "max buckets zero is forwarded, not dropped",
			query: "?max-buckets=0",
			want:  s3.ListBucketsInput{MaxBuckets: aws.Int32(0)},
		},
		{
			// int is 64-bit on every platform this builds for, so a value above
			// int32 parses and is capped rather than refused.
			name:  "max buckets above int32 is capped",
			query: "?max-buckets=2147483648",
			want:  s3.ListBucketsInput{MaxBuckets: aws.Int32(2147483647)},
		},
		{
			name:  "an empty value counts as absent",
			query: "?prefix=&max-buckets=&continuation-token=&bucket-region=",
			want:  s3.ListBucketsInput{},
		},
		{
			name:  "all four together",
			query: "?prefix=logs%2F&max-buckets=7&continuation-token=next&bucket-region=us-west-2",
			want: s3.ListBucketsInput{
				Prefix:            aws.String("logs/"),
				MaxBuckets:        aws.Int32(7),
				ContinuationToken: aws.String("next"),
				BucketRegion:      aws.String("us-west-2"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := RtPxlistBuckets(t, RtPxrequest{
				query: tc.query,
				out:   &s3.ListBucketsOutput{},
			})

			require.Equal(t, http.StatusOK, call.rec.Code)
			require.NotNil(t, call.input, "the backend must have been called")
			assert.Equal(t, aws.ToString(tc.want.Prefix), aws.ToString(call.input.Prefix))
			assert.Equal(t, aws.ToString(tc.want.ContinuationToken), aws.ToString(call.input.ContinuationToken))
			assert.Equal(t, aws.ToString(tc.want.BucketRegion), aws.ToString(call.input.BucketRegion))
			if tc.want.MaxBuckets == nil {
				assert.Nil(t, call.input.MaxBuckets, "max-buckets must stay unset when the client sent none")
			} else {
				require.NotNil(t, call.input.MaxBuckets)
				assert.Equal(t, *tc.want.MaxBuckets, *call.input.MaxBuckets)
			}
		})
	}
}

// A max-buckets the proxy cannot turn into a bucket count is the client's
// mistake and is refused here, not forwarded for the backend to guess at.
func TestRtPxListBucketsRejectsInvalidMaxBuckets(t *testing.T) {
	for _, query := range []string{
		"?max-buckets=-1",
		"?max-buckets=-2147483648",
		"?max-buckets=abc",
		"?max-buckets=1.5",
		"?max-buckets=+%2010",
	} {
		t.Run(query, func(t *testing.T) {
			call := RtPxlistBuckets(t, RtPxrequest{query: query, noBackend: true})

			assert.Equal(t, http.StatusBadRequest, call.rec.Code)
			assert.Equal(t, "application/xml", call.rec.Header().Get("Content-Type"))
			assert.Contains(t, call.body(), "<Code>InvalidArgument</Code>")

			var doc struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
				Message string   `xml:"Message"`
			}
			require.NoError(t, xml.Unmarshal(call.rec.Body.Bytes(), &doc),
				"a refusal must be an S3 <Error> document: %s", call.body())
			assert.Equal(t, "InvalidArgument", doc.Code)
			assert.NotEmpty(t, doc.Message)
		})
	}
}

// Prefix and ContinuationToken are echoed from the backend answer so a paging
// client can carry on; when the backend sends neither, the elements are absent
// rather than present and empty.
func TestRtPxListBucketsEchoesPrefixAndContinuationToken(t *testing.T) {
	t.Run("present in the backend output", func(t *testing.T) {
		call := RtPxlistBuckets(t, RtPxrequest{
			query: "?prefix=logs%2F&max-buckets=1",
			out: &s3.ListBucketsOutput{
				Prefix:            aws.String("logs/"),
				ContinuationToken: aws.String("dG9rZW4="),
				Buckets:           []types.Bucket{{Name: aws.String("logs-1"), CreationDate: aws.Time(time.Unix(0, 0).UTC())}},
			},
		})

		require.Equal(t, http.StatusOK, call.rec.Code)
		assert.Contains(t, call.body(), "<Prefix>logs/</Prefix>")
		assert.Contains(t, call.body(), "<ContinuationToken>dG9rZW4=</ContinuationToken>")

		var doc RtPxlistBucketsDoc
		require.NoError(t, xml.Unmarshal(call.rec.Body.Bytes(), &doc))
		assert.Equal(t, "logs/", doc.Prefix)
		assert.Equal(t, "dG9rZW4=", doc.ContinuationToken)
	})

	t.Run("absent from the backend output", func(t *testing.T) {
		call := RtPxlistBuckets(t, RtPxrequest{
			out: &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("only-bucket"), CreationDate: aws.Time(time.Unix(0, 0).UTC())}},
			},
		})

		require.Equal(t, http.StatusOK, call.rec.Code)
		assert.NotContains(t, call.body(), "<Prefix>",
			"an unpaged listing carries no Prefix element: %s", call.body())
		assert.NotContains(t, call.body(), "<ContinuationToken>",
			"a listing that is not continued carries no ContinuationToken element: %s", call.body())
	})
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
			assert.Contains(t, w.Body.String(), RtPxrootElement)
			var doc RtPxlistBucketsDoc
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
			assert.Empty(t, doc.Buckets.Bucket)
			assert.Empty(t, doc.Owner.ID)
			assert.Contains(t, w.Body.String(), "<Buckets>",
				"the Buckets element must be present even when the account owns none")
		})
	}
}

// A backend that reports buckets with unset fields must still produce a
// parseable document rather than panicking.
func TestRtPxListBucketsToleratesUnsetFields(t *testing.T) {
	w := RtPxdoListBuckets(t, &s3.ListBucketsOutput{Buckets: []types.Bucket{{}}}, nil)

	require.Equal(t, http.StatusOK, w.Code)
	var doc RtPxlistBucketsDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	require.Len(t, doc.Buckets.Bucket, 1)
	assert.Empty(t, doc.Buckets.Bucket[0].Name)
	// A bucket without a creation date omits the element rather than claiming
	// year 0001: an absent date is a gap the client can see, the zero time is a
	// value it would act on.
	assert.Empty(t, doc.Buckets.Bucket[0].CreationDate)
	assert.NotContains(t, w.Body.String(), "<CreationDate>")
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

// A client disconnecting mid-response must not panic the handler, and what did
// reach the wire is either nothing or the whole document.
//
// The old writer streamed the declaration and then encoded into the response,
// so a client that went away in between left a bare declaration behind a
// committed 200 - a truncated document a client cannot tell from a real one.
// Declaration and document now go out in a single write, so there is no state
// in between to assert.
func TestRtPxListBucketsClientDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failAfter int
		wantBody  bool
	}{
		{name: "the client is gone before the document goes out", failAfter: 0, wantBody: false},
		{name: "the client survives the document", failAfter: 1, wantBody: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, backend := RtPxnewHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = middleware.WithClientIdentity(req, "username0")
			w := &RtPxfailingWriter{failAfter: tc.failAfter}

			backend.On("ListBuckets", req.Context(), mock.Anything).
				Return(&s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("b"), CreationDate: aws.Time(time.Unix(1, 0).UTC())}},
				}, nil)

			require.NotPanics(t, func() { handler.HandleListBuckets(w, req) })

			assert.Equal(t, http.StatusOK, w.status)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

			body := w.body.String()
			if !tc.wantBody {
				assert.Empty(t, body, "a failed write must leave no partial document behind")
			} else {
				assert.True(t, strings.HasPrefix(body, RtPxxmlDeclaration+RtPxrootElement),
					"the document goes out in one piece: %q", body)
				assert.True(t, strings.HasSuffix(body, "</ListAllMyBucketsResult>"),
					"the document goes out in one piece: %q", body)
			}
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
			assert.NotContains(t, w.Body.String(), "<ListAllMyBucketsResult",
				"a failed listing must not carry a listing document")
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
	require.NotNil(t, handler.xmlWriter)
	require.NotNil(t, handler.s3Backend)
	require.NotNil(t, handler.logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(nil, errors.New("boom"))

	require.NotPanics(t, func() { handler.HandleListBuckets(w, req) })
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "<Code>InternalError</Code>")
}
