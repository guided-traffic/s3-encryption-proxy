package object

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// ---------------------------------------------------------------------------
// Fixtures. A ranged read addresses plaintext offsets while the backend holds a
// chain of sealed segments, so every test here builds a real stored object with
// the write path and then lets a fake S3 answer byte ranges over those stored
// bytes. The helpers carry their own prefix because the file family owns its
// fixtures (see ObjPut* in objectput_coverage_test.go).
// ---------------------------------------------------------------------------

const ObjGetrangeAESKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// Stride is what one full segment occupies once sealed. Spelled out here rather
// than derived, so a test that asks for a stored window states the number the
// format promises instead of recomputing it from the same constants.
const ObjGetrangeStride = dataencryption.SegmentSize + dataencryption.SegmentOverhead

// ObjGetrangeHandler wires a handler with a real provider behind it:
// "aes" encrypts, "none" is the pass-through provider.
func ObjGetrangeHandler(t *testing.T, backend *MockS3Backend, providerType string) *Handler {
	t.Helper()

	provider := config.EncryptionProvider{Alias: "test-provider", Type: providerType}
	if providerType == "aes" {
		provider.Config = map[string]interface{}{"aes_key": ObjGetrangeAESKey}
	}

	prefix := "s3ep-"
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-provider",
			MetadataKeyPrefix:     &prefix,
			Providers:             []config.EncryptionProvider{provider},
		},
	}
	cfg.Optimizations.StreamingSegmentSize = 1024
	cfg.Optimizations.MultipartUploadConcurrency = 1
	cfg.Optimizations.StreamingThreshold = 5 * 1024 * 1024

	encMgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)
	return NewHandler(backend, encMgr, cfg, testLogEntry())
}

// ObjGetrangeStore stores plaintext the way a single-request write stores it and
// returns what the backend would then hold: the sealed chain and its metadata.
func ObjGetrangeStore(t *testing.T, h *Handler, objectKey string, plaintext []byte) ([]byte, map[string]string) {
	t.Helper()

	write, err := h.encryptionMgr.NewSegmentedWrite(objectKey, bytes.NewReader(plaintext),
		int64(len(plaintext)), nil)
	require.NoError(t, err)

	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)
	require.Equal(t, write.ContentLength, int64(len(stored)),
		"the write announced a Content-Length it did not produce")
	require.Equal(t, dataencryption.FormatID, write.Metadata["s3ep-dek-algorithm"])

	// The stored bytes must never be the plaintext. This is the whole point of
	// the proxy, and it makes the fixture self-checking.
	if len(plaintext) > 0 {
		require.NotEqual(t, plaintext, stored, "fixture stored plaintext at the backend")
	}
	return stored, write.Metadata
}

// ObjGetrangeRequest builds a ranged GET.
func ObjGetrangeRequest(key, rangeHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/b/"+key, nil)
	req.Header.Set("Range", rangeHeader)
	return req
}

// ObjGetrangeAnswer is what S3 answers for a stored byte range: the bytes the
// header asks for, clamped to the object, and the Content-Range that comes with
// them. Tests spell out the stored window they expect the proxy to ask for, so a
// proxy that asks for a different one serves the wrong bytes and says so.
func ObjGetrangeAnswer(t *testing.T, stored []byte, metadata map[string]string, fetch string) *s3.GetObjectOutput {
	t.Helper()

	spec, ok := strings.CutPrefix(fetch, "bytes=")
	require.True(t, ok, "not a byte range: %q", fetch)
	startStr, endStr, ok := strings.Cut(spec, "-")
	require.True(t, ok, "not a byte range: %q", fetch)

	start, err := strconv.ParseInt(startStr, 10, 64)
	require.NoError(t, err)
	end, err := strconv.ParseInt(endStr, 10, 64)
	require.NoError(t, err)
	if end > int64(len(stored))-1 {
		end = int64(len(stored)) - 1
	}
	require.Less(t, start, int64(len(stored)), "the fixture cannot answer a range past the object")

	window := stored[start : end+1]
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(window)),
		ContentLength: aws.Int64(int64(len(window))),
		ContentRange:  aws.String(fmt.Sprintf("bytes %d-%d/%d", start, end, len(stored))),
		ContentType:   aws.String("application/octet-stream"),
		ETag:          aws.String(`"stored-etag"`),
		Metadata:      metadata,
	}
}

// ---------------------------------------------------------------------------
// The window a client asks for is the window it gets.
// ---------------------------------------------------------------------------

// A plaintext range covers a run of segments, and that run is one contiguous
// stretch of stored bytes: one backend request serves it, and what comes back
// is the plaintext window in plaintext offsets.
func TestObjGetRangeReturnsThePlaintextWindow(t *testing.T) {
	// 200000 bytes are four segments, the last one partial.
	const objectSize = 200000

	cases := map[string]struct {
		header     string
		start, end int64  // inclusive plaintext window
		fetch      string // the stored window the proxy must ask for
	}{
		"head":              {"bytes=0-99", 0, 99, "bytes=0-65603"},
		"middle":            {"bytes=70000-140000", 70000, 140000, "bytes=65564-196731"},
		"single_byte":       {"bytes=5000-5000", 5000, 5000, "bytes=0-65603"},
		"tail":              {"bytes=199900-199999", 199900, 199999, "bytes=196692-262295"},
		"clamped_to_object": {"bytes=199900-999999", 199900, 199999, "bytes=196692-1049063"},
		"whole_object":      {"bytes=0-199999", 0, 199999, "bytes=0-262295"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetrangeHandler(t, backend, "aes")

			key := "segmented-range-" + name
			plaintext := ObjGetpayload(objectSize)
			stored, metadata := ObjGetrangeStore(t, h, key, plaintext)

			var inputs []*s3.GetObjectInput
			backend.On("GetObject", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { inputs = append(inputs, args.Get(1).(*s3.GetObjectInput)) }).
				Return(ObjGetrangeAnswer(t, stored, metadata, tc.fetch), nil)

			rr := ObjGetdo(h, ObjGetrangeRequest(key, tc.header), "b", key)

			require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
			require.Len(t, inputs, 1, "a ranged read costs one backend request")
			assert.Equal(t, tc.fetch, aws.ToString(inputs[0].Range),
				"the run of segments is fetched, not the whole object")
			assert.Equal(t, fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, objectSize),
				rr.Header().Get("Content-Range"),
				"the Content-Range must be in plaintext offsets, not stored offsets")
			assert.Equal(t, strconv.FormatInt(tc.end-tc.start+1, 10), rr.Header().Get("Content-Length"))
			assert.Equal(t, "bytes", rr.Header().Get("Accept-Ranges"))
			assert.Equal(t, ObjGetdigest(plaintext[tc.start:tc.end+1]), ObjGetdigest(rr.Body.Bytes()))
		})
	}
}

// Read amplification is the point of the segment size: a one-byte read costs one
// segment plus its framing, whatever the object weighs.
func TestObjGetRangeFetchesOneSegmentForOneByte(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(1 << 20)
	stored, metadata := ObjGetrangeStore(t, h, "one-byte", plaintext)

	// One segment, plus the trailer the provisional window always carries.
	const fetch = "bytes=0-65603"
	var captured *s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
		Return(ObjGetrangeAnswer(t, stored, metadata, fetch), nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("one-byte", "bytes=12345-12345"), "b", "one-byte")

	require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
	require.NotNil(t, captured)
	assert.Equal(t, fetch, aws.ToString(captured.Range))
	assert.Less(t, ObjGetrangeStride+dataencryption.TrailerSize, len(stored),
		"the fixture must be larger than the window it serves")
	assert.Equal(t, plaintext[12345:12346], rr.Body.Bytes())
}

// A suffix range and an open-ended one are relative to the end of the object, so
// the length has to be known before the window can be planned: they cost one
// HEAD, and the GET then asks for the exact planned window rather than a
// provisional one.
func TestObjGetRangeSuffixAndOpenEndedResolveAgainstTheHead(t *testing.T) {
	const objectSize = 200000

	cases := map[string]struct {
		header     string
		start, end int64
		fetch      string
	}{
		"suffix":     {"bytes=-100", 199900, 199999, "bytes=196692-200151"},
		"open_ended": {"bytes=140000-", 140000, 199999, "bytes=131128-200151"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetrangeHandler(t, backend, "aes")

			key := "segmented-tail-" + name
			plaintext := ObjGetpayload(objectSize)
			stored, metadata := ObjGetrangeStore(t, h, key, plaintext)

			backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
				ContentLength: aws.Int64(int64(len(stored))),
				Metadata:      metadata,
			}, nil).Once()

			var captured *s3.GetObjectInput
			backend.On("GetObject", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
				Return(ObjGetrangeAnswer(t, stored, metadata, tc.fetch), nil).Once()

			rr := ObjGetdo(h, ObjGetrangeRequest(key, tc.header), "b", key)

			require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
			backend.AssertNumberOfCalls(t, "HeadObject", 1)
			require.NotNil(t, captured)
			assert.Equal(t, tc.fetch, aws.ToString(captured.Range))
			assert.Equal(t, fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, objectSize),
				rr.Header().Get("Content-Range"))
			assert.Equal(t, ObjGetdigest(plaintext[tc.start:tc.end+1]), ObjGetdigest(rr.Body.Bytes()))
		})
	}
}

// The pass-through provider stores what the client sent, so a ranged read of it
// is the backend's own answer, forwarded.
func TestObjGetRangeNoneProviderPassesThrough(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "none")

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

// ---------------------------------------------------------------------------
// What the proxy refuses to serve.
// ---------------------------------------------------------------------------

// Under an encrypting provider there is no pass-through: an object this proxy
// did not write is refused, and the stored bytes stay at the backend. The
// object exists and the client is allowed, so the answer is InvalidObjectState.
func TestObjGetRangeForeignObjectIsRefused(t *testing.T) {
	// A stored length any chain could have, so the refusal is about the
	// metadata rather than about the arithmetic.
	stored := ObjGetpayload(ObjGetrangeStride + dataencryption.TrailerSize)

	cases := map[string]map[string]string{
		"no_encryption_metadata": {"user": "value"},
		"foreign_algorithm": {
			"s3ep-encrypted-dek":   "ZW5jcnlwdGVkLWRlaw==",
			"s3ep-dek-algorithm":   "aes-ctr",
			"s3ep-kek-fingerprint": "deadbeef",
		},
		"algorithm_missing": {
			"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==",
		},
	}

	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetrangeHandler(t, backend, "aes")

			backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
				Body:          io.NopCloser(bytes.NewReader(stored[:100])),
				ContentLength: aws.Int64(100),
				ContentRange:  aws.String(fmt.Sprintf("bytes 0-99/%d", len(stored))),
				Metadata:      metadata,
			}, nil)

			rr := ObjGetdo(h, ObjGetrangeRequest("foreign", "bytes=0-99"), "b", "foreign")

			require.Equal(t, http.StatusForbidden, rr.Code)
			assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
			assert.NotContains(t, rr.Body.String(), string(stored[:8]),
				"the stored bytes must not reach the client")
		})
	}
}

// A stored length no writer of this format could have produced is refused
// instead of being converted into a fabricated plaintext size.
func TestObjGetRangeStoredLengthIsNotAChainIs403(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "bad-length", plaintext)

	// One byte short of a well-formed chain.
	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(stored[:100])),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String(fmt.Sprintf("bytes 0-99/%d", dataencryption.TrailerSize-1)),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("bad-length", "bytes=0-99"), "b", "bad-length")

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
}

// The segment seal covers the window, so a backend that flips a byte inside it
// does not get that byte served: the read fails where the seal fails, and the
// client receives nothing from the segment that failed.
func TestObjGetRangeWindowIsAuthenticated(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "tampered-range", plaintext)

	tampered := append([]byte(nil), stored...)
	tampered[40] ^= 0xff

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(tampered)),
		ContentLength: aws.Int64(int64(len(tampered))),
		ContentRange:  aws.String(fmt.Sprintf("bytes 0-%d/%d", len(tampered)-1, len(tampered))),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("tampered-range", "bytes=0-99"), "b", "tampered-range")

	// The status line is out before the first segment opens, so a tampered
	// window shows up as a 206 whose body stops rather than as an error status.
	assert.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Empty(t, rr.Body.Bytes(), "nothing that failed its seal may be served")
	assert.NotEqual(t, ObjGetdigest(plaintext[0:100]), ObjGetdigest(rr.Body.Bytes()))
}

// A backend that returns fewer bytes than the window needs cannot make the proxy
// serve the part it did send: the segment is incomplete, so it never opens.
func TestObjGetRangeTruncatedWindowIsNotServed(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "truncated-range", plaintext)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(stored[:50])),
		ContentLength: aws.Int64(int64(len(stored))),
		ContentRange:  aws.String(fmt.Sprintf("bytes 0-%d/%d", len(stored)-1, len(stored))),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("truncated-range", "bytes=0-99"), "b", "truncated-range")

	assert.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Empty(t, rr.Body.Bytes(), "a segment that did not arrive in full is not served")
	assert.Equal(t, "100", rr.Header().Get("Content-Length"),
		"the announced length is the one the client asked for; the body stops short of it")
}

// ---------------------------------------------------------------------------
// Range errors.
// ---------------------------------------------------------------------------

// A range that starts past the end of the object is answered the way S3 answers
// it: 416, code InvalidRange, and a Content-Range naming the real plaintext size.
func TestObjGetRangeUnsatisfiableIs416(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "past-the-end", plaintext)

	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(stored))),
		Metadata:      metadata,
	}, nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("past-the-end", "bytes=99999-"), "b", "past-the-end")

	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, rr.Code)
	assert.Equal(t, "bytes */4096", rr.Header().Get("Content-Range"),
		"416 must name the real plaintext size, in plaintext offsets")
	assert.Equal(t, "InvalidRange", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("ETag"))
	backend.AssertNotCalled(t, "GetObject", mock.Anything, mock.Anything)
}

// A suffix range on an empty object is 416, the way S3 answers any range on an
// empty object. The parser still accepts it - it resolves to a zero-length
// window - and the planner is what refuses it.
func TestObjGetRangeSuffixOnEmptyObjectIs416(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	stored, metadata := ObjGetrangeStore(t, h, "empty", nil)
	require.Len(t, stored, dataencryption.TrailerSize, "an empty object is a bare trailer")

	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(stored))),
		Metadata:      metadata,
	}, nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("empty", "bytes=-5"), "b", "empty")

	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, rr.Code)
	assert.Equal(t, "bytes */0", rr.Header().Get("Content-Range"))
	assert.Equal(t, "InvalidRange", ObjGetparseError(t, rr.Body.Bytes()).Code)

	br, err := parseByteRange("bytes=-5", 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), br.length, "the parser resolves it to nothing")
	_, err = parseByteRange("bytes=0-", 0)
	assert.ErrorIs(t, err, errUnsatisfiableRange)
}

// Multiple ranges and malformed ranges are refused before the backend is
// A Range header the proxy will not act on is ignored and the whole object is
// served, which is what RFC 7233 asks for and what AWS and the backend do. An
// inverted range is different: both bounds are numbers, so the header is
// understood and simply cannot be satisfied.
func TestObjGetRangeIgnoresHeadersItWillNotActOn(t *testing.T) {
	ignored := map[string]string{
		"multiple_ranges": "bytes=0-9,20-29",
		"missing_unit":    "0-99",
		"not_a_number":    "bytes=abc-def",
	}
	for name, header := range ignored {
		t.Run(name, func(t *testing.T) {
			backend := new(MockS3Backend)
			h := ObjGetrangeHandler(t, backend, "aes")
			plaintext := ObjGetpayload(4096)
			stored, metadata := ObjGetrangeStore(t, h, "ignored-"+name, plaintext)

			backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
				Body:          io.NopCloser(bytes.NewReader(stored)),
				ContentLength: aws.Int64(int64(len(stored))),
				Metadata:      metadata,
			}, nil).Once()

			rr := ObjGetdo(h, ObjGetrangeRequest("ignored-"+name, header), "b", "ignored-"+name)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, plaintext, rr.Body.Bytes(), "an ignored Range header must yield the whole object")
			assert.Empty(t, rr.Header().Get("Content-Range"))
		})
	}
}

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
			h := ObjGetrangeHandler(t, backend, "aes")
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

// When the backend ignores the Range header and answers 200 with the whole
// object - which S3 does for a request it will not serve as a range - there is
// no Content-Range to plan against.
func TestObjGetRangeBackendIgnoredRange(t *testing.T) {
	t.Run("encrypted", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetrangeHandler(t, backend, "aes")

		plaintext := ObjGetpayload(4096)
		stored, metadata := ObjGetrangeStore(t, h, "ignored-range", plaintext)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(stored)),
			ContentLength: aws.Int64(int64(len(stored))),
			Metadata:      metadata,
		}, nil)

		rr := ObjGetdo(h, ObjGetrangeRequest("ignored-range", "bytes=0-99"), "b", "ignored-range")

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Equal(t, "InternalError", ObjGetparseError(t, rr.Body.Bytes()).Code)
		assert.NotContains(t, rr.Body.String(), string(stored[:8]))
	})

	// DEFECT (pinned): the pass-through provider answers 206 for a full-object
	// answer, without a Content-Range and with the whole body. RFC 7233 requires
	// Content-Range on a 206, and the client asked for 100 bytes.
	t.Run("none_provider", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetrangeHandler(t, backend, "none")

		object := ObjGetpayload(1000)
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(object)),
			ContentLength: aws.Int64(int64(len(object))),
		}, nil)

		rr := ObjGetdo(h, ObjGetrangeRequest("plain", "bytes=0-99"), "b", "plain")

		assert.Equal(t, http.StatusPartialContent, rr.Code, "known defect: 206 for a full-object answer")
		assert.Empty(t, rr.Header().Get("Content-Range"), "known defect: 206 without Content-Range")
		assert.Equal(t, len(object), rr.Body.Len(), "known defect: the whole object is served")
	})
}

// A Content-Range the proxy cannot parse is a server fault, and the client must
// not receive stored bytes because of it.
func TestObjGetRangeUnparseableContentRangeIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "bad-cr", plaintext)

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(stored[:100])),
		ContentLength: aws.Int64(100),
		ContentRange:  aws.String("octets 0-99/1000"),
		Metadata:      metadata,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("bad-cr", "bytes=0-99"), "b", "bad-cr")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "InternalError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.NotContains(t, rr.Body.String(), string(stored[0:8]))
}

// Metadata in the current format whose wrapped key does not unwrap is a 500, not
// a refusal: the object is one of ours, the key material is what is wrong.
func TestObjGetRangeUndecryptableObjectIs500(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(4096)
	stored, metadata := ObjGetrangeStore(t, h, "undecryptable", plaintext)
	broken := map[string]string{}
	for k, v := range metadata {
		broken[k] = v
	}
	broken["s3ep-encrypted-dek"] = "bm90LWEtd3JhcHBlZC1kZWs="

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(stored)),
		ContentLength: aws.Int64(int64(len(stored))),
		ContentRange:  aws.String(fmt.Sprintf("bytes 0-%d/%d", len(stored)-1, len(stored))),
		Metadata:      broken,
	}, nil)

	rr := ObjGetdo(h, ObjGetrangeRequest("undecryptable", "bytes=0-9"), "b", "undecryptable")

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "DecryptionError", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Empty(t, rr.Header().Get("Content-Range"))
	assert.NotContains(t, rr.Body.String(), string(stored[0:8]))
}

// ---------------------------------------------------------------------------
// Preconditions on the ranged path.
// ---------------------------------------------------------------------------

// The ETag preconditions reach the backend on the one request an explicit range
// costs. DEFECT (pinned): the date preconditions are dropped, and the HEAD that
// a suffix range costs carries none of them at all, so the window can be planned
// against a version the precondition was never checked against.
func TestObjGetRangePreconditionsReachTheBackend(t *testing.T) {
	plaintext := ObjGetpayload(1024)

	t.Run("explicit_range", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetrangeHandler(t, backend, "aes")
		stored, metadata := ObjGetrangeStore(t, h, "cond", plaintext)

		var captured *s3.GetObjectInput
		backend.On("GetObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
			Return(ObjGetrangeAnswer(t, stored, metadata, "bytes=0-65603"), nil)

		req := ObjGetrangeRequest("cond", "bytes=0-9")
		req.Header.Set("If-Match", `"etag-1"`)
		req.Header.Set("If-None-Match", `"etag-2"`)
		req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")

		rr := ObjGetdo(h, req, "b", "cond")

		require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
		require.NotNil(t, captured)
		assert.Equal(t, `"etag-1"`, aws.ToString(captured.IfMatch))
		assert.Equal(t, `"etag-2"`, aws.ToString(captured.IfNoneMatch))
		assert.Nil(t, captured.IfModifiedSince, "known defect: the date preconditions are dropped")
	})

	t.Run("suffix_range_head", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjGetrangeHandler(t, backend, "aes")
		stored, metadata := ObjGetrangeStore(t, h, "cond-suffix", plaintext)

		var head *s3.HeadObjectInput
		backend.On("HeadObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { head = args.Get(1).(*s3.HeadObjectInput) }).
			Return(&s3.HeadObjectOutput{
				ContentLength: aws.Int64(int64(len(stored))),
				Metadata:      metadata,
			}, nil).Once()
		backend.On("GetObject", mock.Anything, mock.Anything).
			Return(ObjGetrangeAnswer(t, stored, metadata, "bytes=0-1091"), nil).Once()

		req := ObjGetrangeRequest("cond-suffix", "bytes=-10")
		req.Header.Set("If-Match", `"etag-1"`)

		rr := ObjGetdo(h, req, "b", "cond-suffix")

		require.Equal(t, http.StatusPartialContent, rr.Code, rr.Body.String())
		require.NotNil(t, head)
		assert.Nil(t, head.IfMatch, "known defect: the HEAD that plans the window carries no precondition")
	})
}

// The suffix path costs two round trips, and a failure on the second one is the
// client's answer - mapped, not swallowed into a 206.
func TestObjGetRangeGetAfterHeadErrorIsMapped(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	plaintext := ObjGetpayload(1024)
	stored, metadata := ObjGetrangeStore(t, h, "vanishes", plaintext)

	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(stored))),
		Metadata:      metadata,
	}, nil).Once()
	// The object is deleted between the two requests.
	backend.On("GetObject", mock.Anything, mock.Anything).Return(nil, &types.NoSuchKey{}).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("vanishes", "bytes=-10"), "b", "vanishes")

	require.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "NoSuchKey", ObjGetparseError(t, rr.Body.Bytes()).Code)
}

// A HEAD the proxy cannot use is refused before a window is planned: an object
// it did not write has no plaintext length to resolve a suffix range against.
func TestObjGetRangeSuffixOnAForeignObjectIsRefused(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetrangeHandler(t, backend, "aes")

	backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
		ContentLength: aws.Int64(1000),
		Metadata:      map[string]string{"user": "value"},
	}, nil).Once()

	rr := ObjGetdo(h, ObjGetrangeRequest("foreign-suffix", "bytes=-10"), "b", "foreign-suffix")

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
	backend.AssertNotCalled(t, "GetObject", mock.Anything, mock.Anything)
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

// parseRangeSpec classifies a header without the object's size: only an explicit
// window can be planned before the length is known.
func TestObjGetParseRangeSpec(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		spec, err := parseRangeSpec("bytes=10-19")
		require.NoError(t, err)
		assert.True(t, spec.explicit)
		assert.Equal(t, int64(10), spec.start)
		assert.Equal(t, int64(19), spec.end)
	})
	t.Run("suffix_needs_the_length", func(t *testing.T) {
		spec, err := parseRangeSpec("bytes=-10")
		require.NoError(t, err)
		assert.False(t, spec.explicit)
	})
	t.Run("open_ended_needs_the_length", func(t *testing.T) {
		spec, err := parseRangeSpec("bytes=10-")
		require.NoError(t, err)
		assert.False(t, spec.explicit)
	})
	t.Run("multiple", func(t *testing.T) {
		_, err := parseRangeSpec("bytes=0-9,20-29")
		assert.ErrorIs(t, err, errMultipleRanges)
	})
	t.Run("missing_unit", func(t *testing.T) {
		_, err := parseRangeSpec("0-99")
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("not_a_number", func(t *testing.T) {
		_, err := parseRangeSpec("bytes=abc-def")
		assert.ErrorIs(t, err, errMalformedRange)
	})
	t.Run("end_before_start", func(t *testing.T) {
		// Both bounds are numbers, so the header is understood; it just asks for
		// a range that cannot exist. The backend answers 416 for it, and so does
		// the proxy.
		_, err := parseRangeSpec("bytes=100-50")
		assert.ErrorIs(t, err, errUnsatisfiableRange)
	})
	t.Run("no_dash", func(t *testing.T) {
		_, err := parseRangeSpec("bytes=100")
		assert.ErrorIs(t, err, errMalformedRange)
	})
}

// The stored total is what the plaintext length is derived from, so a header the
// proxy cannot read that number out of is an error rather than a guess.
func TestObjGetContentRangeTotal(t *testing.T) {
	total, err := contentRangeTotal("bytes 0-99/1000")
	require.NoError(t, err)
	assert.Equal(t, int64(1000), total)

	for name, header := range map[string]string{
		"wrong_unit":   "octets 0-99/1000",
		"no_slash":     "bytes 0-99",
		"not_a_number": "bytes 0-99/many",
		"empty":        "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := contentRangeTotal(header)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected Content-Range")
		})
	}
}
