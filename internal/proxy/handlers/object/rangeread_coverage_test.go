package object

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// ObjGetrangeRequest builds a ranged GET.
func ObjGetrangeRequest(key, rangeHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/b/"+key, nil)
	req.Header.Set("Range", rangeHeader)
	return req
}

// ---------------------------------------------------------------------------
// The window a client asks for is the window it gets.
// ---------------------------------------------------------------------------

func TestObjGetRangeUnencryptedObjectIsPassedThrough(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	object := ObjGetpayload(1000)
	window := object[100:200]

	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(window)),
			ContentLength: aws.Int64(int64(len(window))),
			ContentRange:  aws.String("bytes 100-199/1000"),
			ContentType:   aws.String("text/plain"),
			ETag:          aws.String(`"stored-etag"`),
			Metadata:      map[string]string{"user": "value"},
		}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("plain", "bytes=100-199"), "b", "plain")

	require.Equal(t, http.StatusPartialContent, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "bytes=100-199", aws.ToString(captured.Range))
	assert.Equal(t, "bytes 100-199/1000", rr.Header().Get("Content-Range"))
	assert.Equal(t, "100", rr.Header().Get("Content-Length"))
	assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
	assert.Equal(t, `"stored-etag"`, rr.Header().Get("ETag"))
	assert.Equal(t, "value", rr.Header().Get("x-amz-meta-user"))
	assert.Equal(t, ObjGetdigest(window), ObjGetdigest(rr.Body.Bytes()))
}

// AES-CTR keeps plaintext and ciphertext offsets aligned, so one backend request
// serves the window. What the client gets has to be the plaintext window.
func TestObjGetRangeCTRReturnsThePlaintextWindow(t *testing.T) {
	cases := map[string]struct {
		header     string
		start, end int64 // inclusive plaintext window
	}{
		"head":        {"bytes=0-99", 0, 99},
		"middle":      {"bytes=4096-8191", 4096, 8191},
		"single_byte": {"bytes=5000-5000", 5000, 5000},
		"tail":        {"bytes=9000-9999", 9000, 9999},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

			key := "ctr-range-" + name
			plaintext := ObjGetpayload(10000)
			ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", key, plaintext)

			contentRange := "bytes " + strconv.FormatInt(tc.start, 10) + "-" +
				strconv.FormatInt(tc.end, 10) + "/10000"
			var captured *s3.GetObjectInput
			backend.On("GetObject", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
				Return(&s3.GetObjectOutput{
					Body:          io.NopCloser(bytes.NewReader(ciphertext[tc.start : tc.end+1])),
					ContentLength: aws.Int64(tc.end - tc.start + 1),
					ContentRange:  aws.String(contentRange),
					Metadata:      metadata,
				}, nil)

			rr := ObjGetdo(h, ObjGetrangeRequest(key, tc.header), "b", key)

			require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
			require.NotNil(t, captured)
			assert.Equal(t, tc.header, aws.ToString(captured.Range), "the window is fetched, not the whole object")
			assert.Equal(t, contentRange, rr.Header().Get("Content-Range"))
			assert.Equal(t, ObjGetdigest(plaintext[tc.start:tc.end+1]), ObjGetdigest(rr.Body.Bytes()))
		})
	}
}

// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
// The object HMAC in s3ep-hmac covers the whole object, so a ranged read of an
// AES-CTR object returns bytes the proxy cannot authenticate: a backend that
// flips a byte inside the window is not detected, in any integrity mode.
func TestObjGetRangeCTRWindowIsNotIntegrityChecked(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", "ctr-tampered-range", plaintext)
	require.NotEmpty(t, metadata["s3ep-hmac"])

	window := append([]byte(nil), ciphertext[0:100]...)
	window[7] ^= 0xff

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(window)),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String("bytes 0-99/4096"),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("ctr-tampered-range", "bytes=0-99"), "b", "ctr-tampered-range")

	require.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Len(t, rr.Body.Bytes(), 100)
	assert.NotEqual(t, ObjGetdigest(plaintext[0:100]), ObjGetdigest(rr.Body.Bytes()),
		"the tampered window is delivered unchanged and unflagged")
}

// AES-GCM cannot be decrypted from an offset, so the object is fetched a second
// time in full and the window is taken from the plaintext.
func TestObjGetRangeGCMTakesTheWindowFromAFullDecryption(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-range", plaintext)

	var inputs []*s3.GetObjectInput
	capture := func(args mock.Arguments) { inputs = append(inputs, args.Get(1).(*s3.GetObjectInput)) }
	backend.On("GetObject", mock.Anything, mock.Anything).Run(capture).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext[100:200])),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String("bytes 100-199/" + strconv.Itoa(len(ciphertext))),
		Metadata:      metadata,
	}, nil).Once()
	backend.On("GetObject", mock.Anything, mock.Anything).Run(capture).Return(
		ObjGetgetOutput(ciphertext, metadata), nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("gcm-range", "bytes=100-199"), "b", "gcm-range")

	require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
	require.Len(t, inputs, 2, "GCM needs the whole object")
	assert.Equal(t, "bytes=100-199", aws.ToString(inputs[0].Range))
	assert.Nil(t, inputs[1].Range, "the second request must fetch the whole object")
	assert.Equal(t, "bytes 100-199/4096", rr.Header().Get("Content-Range"),
		"the Content-Range must be in plaintext offsets, not ciphertext offsets")
	assert.Equal(t, "100", rr.Header().Get("Content-Length"))
	assert.Equal(t, ObjGetdigest(plaintext[100:200]), ObjGetdigest(rr.Body.Bytes()))
}

// A suffix range and an open-ended range on the full-decryption path.
func TestObjGetRangeGCMSuffixAndOpenEnded(t *testing.T) {
	cases := map[string]struct {
		header     string
		start, end int
		wantCR     string
	}{
		"suffix":            {"bytes=-100", 3996, 4095, "bytes 3996-4095/4096"},
		"open_ended":        {"bytes=4000-", 4000, 4095, "bytes 4000-4095/4096"},
		"clamped_to_object": {"bytes=4000-99999", 4000, 4095, "bytes 4000-4095/4096"},
		"whole_object":      {"bytes=0-4095", 0, 4095, "bytes 0-4095/4096"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

			key := "gcm-suffix-" + name
			plaintext := ObjGetpayload(4096)
			ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", key, plaintext)

			backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
				Body:          io.NopCloser(bytes.NewReader(nil)),
				ContentLength: aws.Int64(0),
				ContentRange:  aws.String("bytes 0-0/" + strconv.Itoa(len(ciphertext))),
				Metadata:      metadata,
			}, nil).Once()
			backend.On("GetObject", mock.Anything, mock.Anything).Return(
				ObjGetgetOutput(ciphertext, metadata), nil).Once()

			rr := ObjGetdo(h, ObjGetrangeRequest(key, tc.header), "b", key)

			require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
			assert.Equal(t, tc.wantCR, rr.Header().Get("Content-Range"))
			assert.Equal(t, ObjGetdigest(plaintext[tc.start:tc.end+1]), ObjGetdigest(rr.Body.Bytes()))
		})
	}
}

// ---------------------------------------------------------------------------
// Range errors.
// ---------------------------------------------------------------------------

// A range that starts past the end of the object is answered the way S3 answers
// it: 416, code InvalidRange, and a Content-Range naming the real size.
func TestObjGetRangeGCMUnsatisfiableIs416(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(4096)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-416", plaintext)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(nil)),
		ContentLength: aws.Int64(0),
		ContentRange:  aws.String("bytes 0-0/" + strconv.Itoa(len(ciphertext))),
		Metadata:      metadata,
	}, nil).Once()
	backend.On("GetObject", mock.Anything, mock.Anything).Return(
		ObjGetgetOutput(ciphertext, metadata), nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("gcm-416", "bytes=99999-"), "b", "gcm-416")

	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, rr.Code)
	assert.Equal(t, "bytes */4096", rr.Header().Get("Content-Range"),
		"416 must name the real plaintext size, in plaintext offsets")
	assert.Equal(t, "InvalidRange", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("ETag"))
}

// DEFECT (pinned): a suffix range against a zero-length object is treated as a
// satisfiable zero-length range instead of 416 InvalidRange, and the response
// carries the malformed header "Content-Range: bytes 0--1/0". S3 answers 416 for
// any range on an empty object. The explicit forms ("bytes=0-") do return 416,
// so only the suffix form is affected.
func TestObjGetRangeSuffixOnEmptyObjectIsMalformed206(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-empty", nil)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(nil)),
		ContentLength: aws.Int64(0),
		ContentRange:  aws.String("bytes 0-0/" + strconv.Itoa(len(ciphertext))),
		Metadata:      metadata,
	}, nil).Once()
	backend.On("GetObject", mock.Anything, mock.Anything).Return(
		ObjGetgetOutput(ciphertext, metadata), nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("gcm-empty", "bytes=-5"), "b", "gcm-empty")

	assert.Equal(t, http.StatusPartialContent, rr.Code, "known defect: S3 answers 416 here")
	assert.Equal(t, "bytes 0--1/0", rr.Header().Get("Content-Range"), "known defect: malformed Content-Range")
	assert.Empty(t, rr.Body.Bytes())

	// The parser is where it comes from, and the explicit form is handled right.
	br, err := parseByteRange("bytes=-5", 0)
	require.NoError(t, err, "known defect: a suffix range on an empty object is accepted")
	assert.Equal(t, int64(0), br.length)
	_, err = parseByteRange("bytes=0-", 0)
	assert.ErrorIs(t, err, errUnsatisfiableRange)
}

// Multiple ranges and malformed ranges are only rejected on the full-decryption
// path; on every other path the header goes to the backend untouched.
func TestObjGetRangeGCMRejectsMultipleAndMalformedRanges(t *testing.T) {
	cases := map[string]struct {
		header     string
		wantStatus int
		wantCode   string
	}{
		"multiple_ranges":  {"bytes=0-9,20-29", http.StatusNotImplemented, "NotImplemented"},
		"missing_unit":     {"0-99", http.StatusBadRequest, "InvalidArgument"},
		"not_a_number":     {"bytes=abc-def", http.StatusBadRequest, "InvalidArgument"},
		"end_before_start": {"bytes=100-50", http.StatusBadRequest, "InvalidArgument"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

			key := "gcm-bad-" + name
			ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", key, ObjGetpayload(1024))

			backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
				Body:          io.NopCloser(bytes.NewReader(ciphertext)),
				ContentLength: aws.Int64(int64(len(ciphertext))),
				Metadata:      metadata,
			}, nil).Once()
			backend.On("GetObject", mock.Anything, mock.Anything).Return(
				ObjGetgetOutput(ciphertext, metadata), nil).Once()

			rr := ObjGetdo(h, ObjGetrangeRequest(key, tc.header), "b", key)

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantCode, ObjGetparseError(t, rr.Body.Bytes()).Code)
		})
	}
}

// The same malformed header on an object the proxy did not encrypt is forwarded
// to the backend, and whatever the backend answers is what the client sees. The
// two paths therefore disagree about the same request.
func TestObjGetRangeBackendErrorIsMappedThrough(t *testing.T) {
	cases := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"invalid_range":  {&smithy.GenericAPIError{Code: "InvalidRange"}, http.StatusRequestedRangeNotSatisfiable, "InvalidRange"},
		"no_such_key":    {&types.NoSuchKey{}, http.StatusNotFound, "NoSuchKey"},
		"network_broken": {errors.New("connection reset by peer"), http.StatusInternalServerError, "InternalError"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
			backend.On("GetObject", mock.Anything, mock.Anything).Return(nil, tc.err)

			rr := ObjGetdo(h, ObjGetrangeRequest("k", "bytes=0-9"), "b", "k")

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantCode, ObjGetparseError(t, rr.Body.Bytes()).Code)
			if tc.wantStatus == http.StatusRequestedRangeNotSatisfiable {
				// DEFECT (pinned): S3 sends "Content-Range: bytes */<size>" with a
				// 416. A 416 that comes from the backend loses that header here.
				assert.Empty(t, rr.Header().Get("Content-Range"),
					"known defect: no Content-Range on a backend 416")
			}
		})
	}
}

// DEFECT (pinned): when the backend ignores the Range header and answers 200
// with the whole object - which S3 does for a multi-range request - an
// unencrypted object is still answered 206, without a Content-Range and with the
// full body. RFC 7233 requires Content-Range on a 206, and the client asked for
// 100 bytes and gets the object. The encrypted branch handles the same backend
// answer correctly by falling back to a 200.
func TestObjGetRangeBackendIgnoredRangeStillAnswers206(t *testing.T) {
	object := ObjGetpayload(1000)

	t.Run("unencrypted", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(object)),
			ContentLength: aws.Int64(int64(len(object))),
		}, nil)

		rr := ObjGetdo(h, ObjGetrangeRequest("plain", "bytes=0-99"), "b", "plain")

		assert.Equal(t, http.StatusPartialContent, rr.Code, "known defect: 206 for a full-object answer")
		assert.Empty(t, rr.Header().Get("Content-Range"), "known defect: 206 without Content-Range")
		assert.Equal(t, len(object), rr.Body.Len(), "known defect: the whole object is served")
	})

	t.Run("aes_ctr_falls_back_to_200", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)
		plaintext := ObjGetpayload(1000)
		ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", "ctr-no-cr", plaintext)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(
			ObjGetgetOutput(ciphertext, metadata), nil)

		rr := ObjGetdo(h, ObjGetrangeRequest("ctr-no-cr", "bytes=0-99"), "b", "ctr-no-cr")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()))
	})
}

// A Content-Range the proxy cannot parse is a server fault, and the client must
// not receive ciphertext because of it.
func TestObjGetRangeUnparseableContentRangeIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(1000)
	ciphertext, metadata := ObjGetstore(t, h, "aes-ctr", "ctr-bad-cr", plaintext)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext[0:100])),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String("octets 0-99/1000"),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("ctr-bad-cr", "bytes=0-99"), "b", "ctr-bad-cr")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(ciphertext[0:8]))
}

// An object whose recorded algorithm has no known plaintext size cannot be
// ranged over at all.
func TestObjGetRangeUnknownAlgorithmIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	metadata := map[string]string{
		"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
		"s3ep-dek-algorithm": "aes-xyz",
	}
	backend.On("GetObject", mock.Anything, mock.Anything).Return(
		ObjGetgetOutput(ObjGetpayload(512), metadata), nil).Twice()

	rr := ObjGetdo(h, ObjGetrangeRequest("weird", "bytes=0-9"), "b", "weird")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjGetparseError(t, rr.Body.Bytes()).Code)
}

// The backend claims a size the body does not have: the skip to the range start
// runs off the end of the stream. That is a 500, not a short 206.
func TestObjGetRangeShortBodyIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(64)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-short", plaintext)

	// ContentLength announces 4096+28 stored bytes while the body holds 64+28.
	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext)),
		ContentLength: aws.Int64(4096 + 28),
		ContentRange:  aws.String("bytes 0-9/4124"),
		Metadata:      metadata,
	}, nil).Once()
	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext)),
		ContentLength: aws.Int64(4096 + 28),
		Metadata:      metadata,
	}, nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("gcm-short", "bytes=2000-2099"), "b", "gcm-short")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotEqual(t, http.StatusPartialContent, rr.Code)
}

// Decryption that fails outright on the full-decryption path is a 500, and no
// window is emitted.
func TestObjGetRangeUndecryptableObjectIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	metadata := map[string]string{
		"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
		"s3ep-dek-algorithm": "aes-gcm",
	}
	backend.On("GetObject", mock.Anything, mock.Anything).Return(
		ObjGetgetOutput(ObjGetpayload(512), metadata), nil).Twice()

	rr := ObjGetdo(h, ObjGetrangeRequest("undecryptable", "bytes=0-9"), "b", "undecryptable")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("Content-Range"))
}

// ---------------------------------------------------------------------------
// Preconditions on the ranged path.
// ---------------------------------------------------------------------------

// The ETag preconditions reach the backend on the window request. DEFECT
// (pinned): the second, full-object request of the GCM path carries none of
// them, so the window can come from a different version than the one the
// precondition was checked against.
func TestObjGetRangePreconditionsOnlyReachTheFirstRequest(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(1024)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-cond", plaintext)

	var inputs []*s3.GetObjectInput
	capture := func(args mock.Arguments) { inputs = append(inputs, args.Get(1).(*s3.GetObjectInput)) }
	backend.On("GetObject", mock.Anything, mock.Anything).Run(capture).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext[0:10])),
		ContentLength: aws.Int64(10),
		ContentRange:  aws.String("bytes 0-9/" + strconv.Itoa(len(ciphertext))),
		Metadata:      metadata,
	}, nil).Once()
	backend.On("GetObject", mock.Anything, mock.Anything).Run(capture).Return(
		ObjGetgetOutput(ciphertext, metadata), nil).Once()

	req := ObjGetrangeRequest("gcm-cond", "bytes=0-9")
	req.Header.Set("If-Match", `"etag-1"`)
	req.Header.Set("If-None-Match", `"etag-2"`)
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

	rr := ObjGetdo(h, req, "b", "gcm-cond")

	require.Equal(t, http.StatusPartialContent, rr.Code)
	require.Len(t, inputs, 2)
	assert.Equal(t, `"etag-1"`, aws.ToString(inputs[0].IfMatch))
	assert.Equal(t, `"etag-2"`, aws.ToString(inputs[0].IfNoneMatch))
	assert.Nil(t, inputs[0].IfModifiedSince, "known defect: the date preconditions are dropped here too")
	assert.Nil(t, inputs[1].IfMatch, "known defect: the second fetch carries no precondition")
	assert.Nil(t, inputs[1].IfNoneMatch)
}

// ---------------------------------------------------------------------------
// Units.
// ---------------------------------------------------------------------------

func TestObjGetWriteRangeError(t *testing.T) {
	h := newResponseTestHandler(nil)

	cases := map[string]struct {
		err          error
		wantStatus   int
		wantCode     string
		wantCRHeader string
	}{
		"unsatisfiable": {errUnsatisfiableRange, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "bytes */4096"},
		"multiple":      {errMultipleRanges, http.StatusNotImplemented, "NotImplemented", ""},
		"malformed":     {errMalformedRange, http.StatusBadRequest, "InvalidArgument", ""},
		"unknown":       {errors.New("something else"), http.StatusBadRequest, "InvalidArgument", ""},
		"wrapped_unsatisfiable": {
			errors.Join(errors.New("context"), errUnsatisfiableRange),
			http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "bytes */4096",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.writeRangeError(rr, tc.err, 4096)

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantCRHeader, rr.Header().Get("Content-Range"))
			assert.Equal(t, tc.wantCode, ObjGetparseError(t, rr.Body.Bytes()).Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
		})
	}
}

// writeRangeResponse must not invent headers it was not given, and a negative
// length (an unknown one) must not be declared.
func TestObjGetWriteRangeResponseMinimal(t *testing.T) {
	h := newResponseTestHandler(nil)

	rr := httptest.NewRecorder()
	h.writeRangeResponse(rr, bytes.NewReader([]byte("abc")), "", -1, &s3.GetObjectOutput{})

	require.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Equal(t, []string{"accept-ranges"}, headerNames(rr.Result().Header))
	assert.Equal(t, "abc", rr.Body.String())
}

// A body that dies mid-window cannot change the status that is already out.
func TestObjGetWriteRangeResponseBodyFailure(t *testing.T) {
	h := newResponseTestHandler(nil)

	rr := httptest.NewRecorder()
	body := io.MultiReader(bytes.NewReader([]byte("part")), ObjGeterrReader{err: errors.New("broken")})
	h.writeRangeResponse(rr, body, "bytes 0-9/10", 10, &s3.GetObjectOutput{})

	assert.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Equal(t, "part", rr.Body.String())
	assert.Equal(t, "10", rr.Header().Get("Content-Length"))
}

// parseByteRange corner cases the existing table does not reach.
func TestObjGetParseByteRangeEdgeCases(t *testing.T) {
	t.Run("start_overflows_int64", func(t *testing.T) {
		_, err := parseByteRange("bytes=99999999999999999999-", 1000)
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("suffix_overflows_int64", func(t *testing.T) {
		_, err := parseByteRange("bytes=-99999999999999999999", 1000)
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("end_overflows_int64", func(t *testing.T) {
		_, err := parseByteRange("bytes=0-99999999999999999999", 1000)
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("inner_whitespace", func(t *testing.T) {
		br, err := parseByteRange("bytes= 10 - 19 ", 1000)
		require.NoError(t, err)
		assert.Equal(t, int64(10), br.start)
		assert.Equal(t, int64(10), br.length)
	})
	t.Run("last_byte_of_one_byte_object", func(t *testing.T) {
		br, err := parseByteRange("bytes=0-0", 1)
		require.NoError(t, err)
		assert.Equal(t, int64(0), br.start)
		assert.Equal(t, int64(1), br.length)
		assert.Equal(t, "bytes 0-0/1", br.contentRange())
		assert.Equal(t, int64(0), br.end())
	})
	t.Run("empty_header", func(t *testing.T) {
		_, err := parseByteRange("", 1000)
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("only_unit", func(t *testing.T) {
		_, err := parseByteRange("bytes=", 1000)
		assert.ErrorIs(t, err, errMalformedRange)
	})
}

// An AES-CTR object whose metadata names no key material fails the ranged read
// with a 500 and no ciphertext in the body.
func TestObjGetRangeCTRDecryptionReaderFailureIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	ciphertext := ObjGetpayload(100)
	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext)),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String("bytes 0-99/1000"),
		Metadata: map[string]string{
			"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm": "aes-ctr",
		},
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("ctr-nokey", "bytes=0-99"), "b", "ctr-nokey")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(ciphertext[:8]))
	assert.Empty(t, rr.Header().Get("Content-Range"))
}

// The full-decryption path issues a second request, and a failure there is the
// client's answer - mapped, not swallowed into a 206.
func TestObjGetRangeSecondFetchErrorIsMapped(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend, config.HMACVerificationStrict)

	plaintext := ObjGetpayload(1024)
	ciphertext, metadata := ObjGetstore(t, h, "aes-gcm", "gcm-vanishes", plaintext)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext[0:10])),
		ContentLength: aws.Int64(10),
		ContentRange:  aws.String("bytes 0-9/" + strconv.Itoa(len(ciphertext))),
		Metadata:      metadata,
	}, nil).Once()
	// The object is deleted between the two requests.
	backend.On("GetObject", mock.Anything, mock.Anything).Return(nil, &types.NoSuchKey{}).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("gcm-vanishes", "bytes=0-9"), "b", "gcm-vanishes")

	require.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "NoSuchKey", ObjGetparseError(t, rr.Body.Bytes()).Code)
}

func TestObjGetContentRangeStartWithoutADash(t *testing.T) {
	_, err := contentRangeStart("bytes 099/1000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected Content-Range")
}
