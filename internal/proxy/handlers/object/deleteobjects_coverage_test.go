package object

import (
	"crypto/md5" // #nosec G501 - Content-MD5 is the digest S3 defines for this request
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// POST /{bucket}?delete - DeleteObjects. A real XML API in both directions, so
// this file works entirely on documents: what goes in, which backend call it
// becomes, what comes back out. The storage-format change (ADR 0003) does not
// touch this path.
// ---------------------------------------------------------------------------

// ObjMiscdeleteResult mirrors the AWS DeleteResult document so the response is
// asserted as a client parses it, not as a string.
type ObjMiscdeleteResult struct {
	XMLName xml.Name `xml:"DeleteResult"`
	Deleted []struct {
		Key                   string `xml:"Key"`
		VersionID             string `xml:"VersionId"`
		DeleteMarker          bool   `xml:"DeleteMarker"`
		DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId"`
	} `xml:"Deleted"`
	Errors []struct {
		Key       string `xml:"Key"`
		Code      string `xml:"Code"`
		Message   string `xml:"Message"`
		VersionID string `xml:"VersionId"`
	} `xml:"Error"`
}

func ObjMiscparseDeleteResult(t *testing.T, body []byte) ObjMiscdeleteResult {
	t.Helper()
	var doc ObjMiscdeleteResult
	require.NoError(t, xml.Unmarshal(body, &doc), "the answer must be a parseable DeleteResult")
	return doc
}

// ObjMiscbodyDigest sets the body digest S3 requires on a multi-object delete and
// this proxy verifies (ADR 0012 D14). Every delete test carries one, because a
// request without it never reaches the handler's own logic.
func ObjMiscbodyDigest(req *http.Request, body string) *http.Request {
	sum := md5.Sum([]byte(body)) // #nosec G401 - Content-MD5 is the digest S3 defines here
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	return req
}

// ObjMiscdeleteObjects posts a Delete document through the exported wrapper the
// router registers.
func ObjMiscdeleteObjects(h *Handler, bucket, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/"+bucket+"?delete", strings.NewReader(body))
	return ObjMiscdoFunc(h.HandleDeleteObjects, ObjMiscbodyDigest(req, body), map[string]string{"bucket": bucket})
}

// A well-formed multi-key document becomes exactly one DeleteObjects call
// carrying every key, and the answer lists every key as deleted.
func TestObjMiscDeleteObjectsHappyPath(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	var captured *s3.DeleteObjectsInput
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectsInput) }).
		Return(&s3.DeleteObjectsOutput{Deleted: []types.DeletedObject{
			{Key: aws.String("a.txt")},
			{Key: aws.String("dir/b.txt")},
		}}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt", `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>a.txt</Key></Object>
  <Object><Key>dir/b.txt</Key></Object>
</Delete>`)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
	assert.True(t, strings.HasPrefix(rr.Body.String(), xml.Header),
		"the answer has to start with the XML declaration")

	require.NotNil(t, captured)
	assert.Equal(t, "bkt", aws.ToString(captured.Bucket))
	require.Len(t, captured.Delete.Objects, 2)
	assert.Equal(t, "a.txt", aws.ToString(captured.Delete.Objects[0].Key))
	assert.Equal(t, "dir/b.txt", aws.ToString(captured.Delete.Objects[1].Key))
	assert.Nil(t, captured.Delete.Objects[0].VersionId)
	assert.False(t, aws.ToBool(captured.Delete.Quiet))

	doc := ObjMiscparseDeleteResult(t, rr.Body.Bytes())
	require.Len(t, doc.Deleted, 2)
	assert.Equal(t, "a.txt", doc.Deleted[0].Key)
	assert.Equal(t, "dir/b.txt", doc.Deleted[1].Key)
	assert.Empty(t, doc.Errors)
	backend.AssertExpectations(t)
}

// A per-object VersionId is forwarded; without it the current version would be
// deleted instead, which on a versioned bucket is a different object.
func TestObjMiscDeleteObjectsForwardsPerObjectVersionID(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	var captured *s3.DeleteObjectsInput
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectsInput) }).
		Return(&s3.DeleteObjectsOutput{Deleted: []types.DeletedObject{{
			Key:                   aws.String("a.txt"),
			VersionId:             aws.String("v1"),
			DeleteMarker:          aws.Bool(true),
			DeleteMarkerVersionId: aws.String("dm7"),
		}}}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt", `<Delete>
  <Object><Key>a.txt</Key><VersionId>v1</VersionId></Object>
  <Object><Key>b.txt</Key></Object>
</Delete>`)

	require.NotNil(t, captured)
	require.Len(t, captured.Delete.Objects, 2)
	assert.Equal(t, "v1", aws.ToString(captured.Delete.Objects[0].VersionId))
	assert.Nil(t, captured.Delete.Objects[1].VersionId, "an absent VersionId stays absent")

	doc := ObjMiscparseDeleteResult(t, rr.Body.Bytes())
	require.Len(t, doc.Deleted, 1)
	assert.Equal(t, "v1", doc.Deleted[0].VersionID)
	assert.True(t, doc.Deleted[0].DeleteMarker)
	assert.Equal(t, "dm7", doc.Deleted[0].DeleteMarkerVersionID)
}

// The Quiet flag is parsed and forwarded verbatim; the proxy renders whatever
// the backend then reports.
func TestObjMiscDeleteObjectsQuietFlagIsForwarded(t *testing.T) {
	cases := map[string]struct {
		body      string
		wantQuiet bool
	}{
		"quiet_true":   {`<Delete><Quiet>true</Quiet><Object><Key>a</Key></Object></Delete>`, true},
		"quiet_false":  {`<Delete><Quiet>false</Quiet><Object><Key>a</Key></Object></Delete>`, false},
		"quiet_absent": {`<Delete><Object><Key>a</Key></Object></Delete>`, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			var captured *s3.DeleteObjectsInput
			backend.On("DeleteObjects", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectsInput) }).
				Return(&s3.DeleteObjectsOutput{}, nil)

			rr := ObjMiscdeleteObjects(h, "bkt", tc.body)

			assert.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, captured)
			assert.Equal(t, tc.wantQuiet, aws.ToBool(captured.Delete.Quiet))
		})
	}
}

// A quiet backend answer carries no Deleted entries, and the proxy must not
// invent any: the document is an empty DeleteResult, not a list of successes.
func TestObjMiscDeleteObjectsQuietAnswerListsNothing(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt",
		`<Delete><Quiet>true</Quiet><Object><Key>a</Key></Object></Delete>`)

	assert.Equal(t, http.StatusOK, rr.Code)
	doc := ObjMiscparseDeleteResult(t, rr.Body.Bytes())
	assert.Empty(t, doc.Deleted)
	assert.Empty(t, doc.Errors)
	assert.Contains(t, rr.Body.String(), "<DeleteResult ")
}

// A partial failure has to reach the client as <Error> entries alongside the
// successes, with the backend's own code and message. Anything else lets a
// caller believe it deleted a key it did not.
func TestObjMiscDeleteObjectsPartialFailureIsReported(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{
			Deleted: []types.DeletedObject{{Key: aws.String("ok.txt")}},
			Errors: []types.Error{
				{Key: aws.String("denied.txt"), Code: aws.String("AccessDenied"), Message: aws.String("Access Denied")},
				{Key: aws.String("gone.txt"), Code: aws.String("NoSuchVersion"), Message: aws.String("no version"),
					VersionId: aws.String("v9")},
			},
		}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt", `<Delete>
  <Object><Key>ok.txt</Key></Object>
  <Object><Key>denied.txt</Key></Object>
  <Object><Key>gone.txt</Key></Object>
</Delete>`)

	// AWS answers 200 for a partial failure too; the failures live in the body.
	assert.Equal(t, http.StatusOK, rr.Code)
	doc := ObjMiscparseDeleteResult(t, rr.Body.Bytes())

	require.Len(t, doc.Deleted, 1)
	assert.Equal(t, "ok.txt", doc.Deleted[0].Key)

	require.Len(t, doc.Errors, 2)
	assert.Equal(t, "denied.txt", doc.Errors[0].Key)
	assert.Equal(t, "AccessDenied", doc.Errors[0].Code)
	assert.Equal(t, "Access Denied", doc.Errors[0].Message)
	assert.Empty(t, doc.Errors[0].VersionID)
	assert.Equal(t, "gone.txt", doc.Errors[1].Key)
	assert.Equal(t, "NoSuchVersion", doc.Errors[1].Code)
	assert.Equal(t, "v9", doc.Errors[1].VersionID)
}

// The batch-delete answer carries the S3 namespace, like every other response
// document (ADR 0008 D3). It did not until 2026-09-12, and this test pinned the
// gap as expected behaviour: a namespace-aware parser matching on the qualified
// name saw no result at all.
func TestObjMiscDeleteObjectsResponseCarriesTheS3Namespace(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{Deleted: []types.DeletedObject{{Key: aws.String("a")}}}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt", `<Delete><Object><Key>a</Key></Object></Delete>`)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`,
		"AWS namespaces this document and so does the proxy")

	// And it still parses as the document it claims to be.
	var doc struct {
		XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
		Deleted []struct {
			Key string `xml:"Key"`
		} `xml:"Deleted"`
	}
	require.NoError(t, xml.Unmarshal(rr.Body.Bytes(), &doc))
	require.Len(t, doc.Deleted, 1)
	assert.Equal(t, "a", doc.Deleted[0].Key)
}

// Malformed XML is refused before the backend is touched.
func TestObjMiscDeleteObjectsMalformedXMLIsRefused(t *testing.T) {
	cases := map[string]string{
		"unclosed_element": `<Delete><Object><Key>a.txt</Object></Delete>`,
		"not_xml_at_all":   `this is not xml`,
		"truncated":        `<Delete><Object><Key>a`,
		"binary_junk":      "\x00\x01\x02\x03",
		"stray_close":      `</Delete>`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			rr := ObjMiscdeleteObjects(h, "bkt", body)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
			doc := ObjMiscparseError(t, rr.Body.Bytes())
			assert.Equal(t, "MalformedXML", doc.Code)
			assert.Equal(t, "The XML you provided was not well-formed", doc.Message)
			backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
		})
	}
}

// A Delete document that parses but names no object is still not a valid Delete:
// it is refused with 400 MalformedXML, the answer S3 gives, and never becomes an
// empty backend call (ADR 0006 D2, ADR 0007 D1).
func TestObjMiscDeleteObjectsEmptyDocumentIsRefused(t *testing.T) {
	cases := map[string]string{
		"empty_delete_element": `<Delete></Delete>`,
		"self_closing":         `<Delete/>`,
		"quiet_only":           `<Delete><Quiet>true</Quiet></Delete>`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)

			// Stubbed so the unwanted call fails an assertion instead of
			// panicking the whole package run.
			backend.On("DeleteObjects", mock.Anything, mock.Anything).
				Return(&s3.DeleteObjectsOutput{}, nil)

			rr := ObjMiscdeleteObjects(h, "bkt", body)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
			assert.Equal(t, "MalformedXML", ObjMiscparseError(t, rr.Body.Bytes()).Code)
			backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
		})
	}
}

// A completely empty body is a different case: xml.Unmarshal reports EOF, so it
// is refused. Pinned because it is the only empty-ish body that is.
func TestObjMiscDeleteObjectsEmptyBodyIsMalformed(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	rr := ObjMiscdeleteObjects(h, "bkt", "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "MalformedXML", ObjMiscparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
}

// An <Object> with no <Key> makes the document invalid: 400 MalformedXML. The
// proxy re-serialises this document, so accepting it would author a delete for
// the empty key on the client's behalf (ADR 0007 D1/D8, ADR 0006 D2).
func TestObjMiscDeleteObjectsObjectWithoutAKeyIsRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	// Stubbed so the unwanted call fails an assertion instead of panicking the
	// whole package run.
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt", `<Delete><Object></Object></Delete>`)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "MalformedXML", ObjMiscparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
}

// Above 1000 objects the document is refused with 400 MalformedXML, as S3 does,
// and the body read is bounded with it so one request cannot buffer a document of
// any size and become an unbounded backend call (ADR 0006 D2, ADR 0011 D5).
func TestObjMiscDeleteObjectsRefusesAboveTheThousandKeyLimit(t *testing.T) {
	const count = 1001

	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	// Stubbed so the unwanted call fails an assertion instead of panicking the
	// whole package run.
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{}, nil)

	var body strings.Builder
	body.WriteString("<Delete>")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&body, "<Object><Key>key-%d</Key></Object>", i)
	}
	body.WriteString("</Delete>")

	rr := ObjMiscdeleteObjects(h, "bkt", body.String())

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "MalformedXML", ObjMiscparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
}

// ObjMiscerrReader fails on the first Read, the way a client that disconnects
// mid-body does.
type ObjMiscerrReader struct{ err error }

func (r ObjMiscerrReader) Read([]byte) (int, error) { return 0, r.err }
func (r ObjMiscerrReader) Close() error             { return nil }

// A body that cannot be read is a transport fault, answered 400 IncompleteBody
// word for word as PUT and UploadPart answer it; InvalidRequest stays the answer
// for a request carrying no digest at all (ADR 0012 D14, ADR 0007 D8).
func TestObjMiscDeleteObjectsBodyReadErrorIsRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	req := ObjMiscbodyDigest(
		httptest.NewRequest(http.MethodPost, "/bkt?delete", strings.NewReader("<Delete/>")), "<Delete/>")
	req.Body = ObjMiscerrReader{err: errors.New("unexpected EOF")}
	rr := ObjMiscdoFunc(h.HandleDeleteObjects, req, map[string]string{"bucket": "bkt"})

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	doc := ObjMiscparseError(t, rr.Body.Bytes())
	assert.Equal(t, "IncompleteBody", doc.Code)
	assert.Equal(t, "The request body terminated before the declared number of bytes was read", doc.Message)
	backend.AssertNotCalled(t, "DeleteObjects", mock.Anything, mock.Anything)
}

// A backend failure is mapped to the S3 status and code the backend reported,
// and the resource is the bucket alone - there is no single key to name.
func TestObjMiscDeleteObjectsBackendErrorsAreMapped(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"no_such_bucket": {&types.NoSuchBucket{}, http.StatusNotFound, "NoSuchBucket"},
		"access_denied": {&smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"},
			http.StatusForbidden, "AccessDenied"},
		"malformed_xml_from_backend": {&smithy.GenericAPIError{Code: "MalformedXML"},
			http.StatusBadRequest, "MalformedXML"},
		"slow_down": {&smithy.GenericAPIError{Code: "SlowDown"},
			http.StatusServiceUnavailable, "SlowDown"},
		"network_error": {errors.New("dial tcp 10.0.0.1:9000: connect: connection refused"),
			http.StatusInternalServerError, "InternalError"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)
			backend.On("DeleteObjects", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjMiscdeleteObjects(h, "bkt", `<Delete><Object><Key>a</Key></Object></Delete>`)

			assert.Equal(t, tc.wantStatus, rr.Code)
			doc := ObjMiscparseError(t, rr.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, "bkt", doc.Resource)
			assert.NotContains(t, rr.Body.String(), "10.0.0.1")
		})
	}
}

// A key with XML metacharacters must come back escaped, not break the document.
func TestObjMiscDeleteObjectsEscapesKeysInTheResponse(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	nasty := `a&b<c>"d'e`
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{
			Deleted: []types.DeletedObject{{Key: aws.String(nasty)}},
			Errors:  []types.Error{{Key: aws.String(nasty), Code: aws.String("AccessDenied")}},
		}, nil)

	rr := ObjMiscdeleteObjects(h, "bkt",
		`<Delete><Object><Key>a&amp;b&lt;c&gt;"d'e</Key></Object></Delete>`)

	assert.Equal(t, http.StatusOK, rr.Code)
	doc := ObjMiscparseDeleteResult(t, rr.Body.Bytes())
	require.Len(t, doc.Deleted, 1)
	assert.Equal(t, nasty, doc.Deleted[0].Key)
	require.Len(t, doc.Errors, 1)
	assert.Equal(t, nasty, doc.Errors[0].Key)
}

// ObjMiscfailWriter fails the nth Write, so the two write branches at the end of
// the handler can be reached. Everything else behaves like a recorder.
type ObjMiscfailWriter struct {
	header  http.Header
	status  int
	writes  int
	failOn  int
	written []byte
}

func ObjMiscnewFailWriter(failOn int) *ObjMiscfailWriter {
	return &ObjMiscfailWriter{header: http.Header{}, failOn: failOn}
}

func (w *ObjMiscfailWriter) Header() http.Header { return w.header }

func (w *ObjMiscfailWriter) WriteHeader(status int) { w.status = status }

func (w *ObjMiscfailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failOn {
		return 0, errors.New("client went away")
	}
	w.written = append(w.written, p...)
	return len(p), nil
}

// A client that disconnects while the answer is being written must not take the
// handler down, and the status is already committed either way.
func TestObjMiscDeleteObjectsSurvivesAFailingResponseWriter(t *testing.T) {
	for name, failOn := range map[string]int{"xml_declaration": 1, "document_body": 2} {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjMiscnewHandler(t, backend)
			backend.On("DeleteObjects", mock.Anything, mock.Anything).
				Return(&s3.DeleteObjectsOutput{Deleted: []types.DeletedObject{{Key: aws.String("a")}}}, nil)

			w := ObjMiscnewFailWriter(failOn)
			req := ObjMiscbodyDigest(httptest.NewRequest(http.MethodPost, "/bkt?delete",
				strings.NewReader(`<Delete><Object><Key>a</Key></Object></Delete>`)),
				`<Delete><Object><Key>a</Key></Object></Delete>`)
			h.handleDeleteObjects(w, req, "bkt")

			assert.Equal(t, http.StatusOK, w.status)
			if failOn == 1 {
				assert.Empty(t, w.written, "nothing is written after the declaration fails")
			} else {
				assert.Equal(t, xml.Header, string(w.written))
			}
		})
	}
}

// The handler reads the whole body before parsing. A large document is accepted
// and forwarded; this pins that there is no size guard on the read.
func TestObjMiscDeleteObjectsReadsTheWholeBodyUnbounded(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	backend.On("DeleteObjects", mock.Anything, mock.Anything).
		Return(&s3.DeleteObjectsOutput{}, nil)

	// One object, but padded with a comment far larger than the document needs.
	padding := strings.Repeat("x", 1<<20)
	body := "<Delete><!--" + padding + "--><Object><Key>a</Key></Object></Delete>"

	req := ObjMiscbodyDigest(httptest.NewRequest(http.MethodPost, "/bkt?delete", strings.NewReader(body)), body)
	req.ContentLength = int64(len(body))
	rr := ObjMiscdoFunc(h.HandleDeleteObjects, req, map[string]string{"bucket": "bkt"})

	assert.Equal(t, http.StatusOK, rr.Code,
		"a 1 MiB document is buffered whole; nothing caps the request body")
}

// The bucket comes from the mux vars, so a request routed without them still
// answers rather than panicking - with an empty bucket the backend rejects.
func TestObjMiscDeleteObjectsWithoutMuxVars(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)
	backend.On("DeleteObjects", mock.Anything, mock.MatchedBy(func(in *s3.DeleteObjectsInput) bool {
		return aws.ToString(in.Bucket) == ""
	})).Return(nil, &smithy.GenericAPIError{Code: "InvalidBucketName"})

	req := ObjMiscbodyDigest(httptest.NewRequest(http.MethodPost, "/?delete",
		strings.NewReader(`<Delete><Object><Key>a</Key></Object></Delete>`)),
		`<Delete><Object><Key>a</Key></Object></Delete>`)
	rr := ObjMiscdoFunc(h.HandleDeleteObjects, req, map[string]string{})

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "InvalidBucketName", ObjMiscparseError(t, rr.Body.Bytes()).Code)
}

// Sanity check on the fixture itself: the reader helper really is what the
// handler consumed, so the read-error test above is not vacuous.
func TestObjMiscErrReaderReturnsItsError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := io.ReadAll(ObjMiscerrReader{err: sentinel})
	assert.ErrorIs(t, err, sentinel)
}

// Both delete paths carry the ownership precondition and still drop the other
// two headers AWS defines for a delete.
//
//   - x-amz-expected-bucket-owner is forwarded (ADR 0007 D14). It was the one
//     drop that failed open: AWS answers 403 AccessDenied when the bucket has a
//     different owner, while the proxy deleted the object and answered success,
//     so the guard the client asked for was never applied.
//   - x-amz-bypass-governance-retention and x-amz-mfa are still dropped. Both
//     fail closed — without them the backend refuses the delete rather than
//     performing one it should not — so neither is the silent-success shape
//     ADR 0007 D1 forbids. They are recorded here, not endorsed.
func TestObjMiscDeletePathsCarryTheOwnerGuardAndDropTheRest(t *testing.T) {
	t.Run("DeleteObject", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)

		var captured *s3.DeleteObjectInput
		backend.On("DeleteObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectInput) }).
			Return(&s3.DeleteObjectOutput{}, nil)

		req := httptest.NewRequest(http.MethodDelete, "/b/k", nil)
		req.Header.Set("x-amz-expected-bucket-owner", "111122223333")
		req.Header.Set("x-amz-bypass-governance-retention", "true")
		req.Header.Set("x-amz-mfa", "arn:aws:iam::111122223333:mfa/user 123456")
		req.Header.Set("x-amz-request-payer", "requester")

		rr := ObjMiscdo(h, req, "b", "k")

		assert.Equal(t, http.StatusNoContent, rr.Code)
		require.NotNil(t, captured)
		assert.Equal(t, "111122223333", aws.ToString(captured.ExpectedBucketOwner),
			"the ownership precondition reaches the backend that can answer it")
		assert.Nil(t, captured.BypassGovernanceRetention)
		assert.Nil(t, captured.MFA)
		assert.Empty(t, string(captured.RequestPayer))
	})

	t.Run("DeleteObjects", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)

		var captured *s3.DeleteObjectsInput
		backend.On("DeleteObjects", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectsInput) }).
			Return(&s3.DeleteObjectsOutput{}, nil)

		const doc = `<Delete><Object><Key>a</Key></Object></Delete>`
		req := ObjMiscbodyDigest(
			httptest.NewRequest(http.MethodPost, "/b?delete", strings.NewReader(doc)), doc)
		req.Header.Set("x-amz-expected-bucket-owner", "111122223333")
		req.Header.Set("x-amz-bypass-governance-retention", "true")
		req.Header.Set("x-amz-mfa", "arn:aws:iam::111122223333:mfa/user 123456")

		rr := ObjMiscdoFunc(h.HandleDeleteObjects, req, map[string]string{"bucket": "b"})

		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, captured)
		assert.Equal(t, "111122223333", aws.ToString(captured.ExpectedBucketOwner))
		assert.Nil(t, captured.BypassGovernanceRetention)
		assert.Nil(t, captured.MFA)
		// The digest the proxy verified is its own business: it describes the
		// document, and the SDK computes what the backend needs (ADR 0012 D8).
		assert.Empty(t, string(captured.ChecksumAlgorithm))
	})
}
