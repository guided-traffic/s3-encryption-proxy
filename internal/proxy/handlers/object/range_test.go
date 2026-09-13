package object

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestParseByteRange(t *testing.T) {
	const total = 1000

	cases := []struct {
		name      string
		header    string
		wantStart int64
		wantLen   int64
		wantCR    string
	}{
		{"explicit_window", "bytes=0-99", 0, 100, "bytes 0-99/1000"},
		{"mid_object", "bytes=100-199", 100, 100, "bytes 100-199/1000"},
		{"open_ended", "bytes=900-", 900, 100, "bytes 900-999/1000"},
		{"whole_object", "bytes=0-999", 0, 1000, "bytes 0-999/1000"},
		{"end_beyond_object_is_clamped", "bytes=990-5000", 990, 10, "bytes 990-999/1000"},
		{"suffix", "bytes=-100", 900, 100, "bytes 900-999/1000"},
		{"suffix_larger_than_object", "bytes=-5000", 0, 1000, "bytes 0-999/1000"},
		{"single_byte", "bytes=42-42", 42, 1, "bytes 42-42/1000"},
		{"last_byte", "bytes=999-999", 999, 1, "bytes 999-999/1000"},
		// kopia reads its pack blobs like this.
		{"small_read_at_offset", "bytes=32-63", 32, 32, "bytes 32-63/1000"},
		{"whitespace_tolerated", " bytes=10-19 ", 10, 10, "bytes 10-19/1000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br, err := parseByteRange(tc.header, total)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStart, br.start, "start")
			assert.Equal(t, tc.wantLen, br.length, "length")
			assert.Equal(t, tc.wantCR, br.contentRange())
		})
	}
}

func TestParseByteRange_Errors(t *testing.T) {
	const total = 1000

	cases := map[string]struct {
		header string
		want   error
	}{
		"start_past_end":     {"bytes=1000-1099", errUnsatisfiableRange},
		"start_far_past_end": {"bytes=999999-", errUnsatisfiableRange},
		"zero_suffix":        {"bytes=-0", errUnsatisfiableRange},
		"multiple_ranges":    {"bytes=0-9,20-29", errMultipleRanges},
		"missing_unit":       {"0-99", errMalformedRange},
		"wrong_unit":         {"items=0-99", errMalformedRange},
		"no_dash":            {"bytes=100", errMalformedRange},
		"end_before_start":   {"bytes=100-50", errMalformedRange},
		"negative_start":     {"bytes=-100-200", errMalformedRange},
		"empty_spec":         {"bytes=-", errMalformedRange},
		"not_a_number":       {"bytes=abc-def", errMalformedRange},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseByteRange(tc.header, total)
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, tc.want), "got %v, want %v", err, tc.want)
		})
	}
}

// A zero-length object can satisfy no range at all.
func TestParseByteRange_EmptyObject(t *testing.T) {
	_, err := parseByteRange("bytes=0-", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUnsatisfiableRange))
}

// A 206 has to carry the same identity and entity headers as the 200 for the same
// object: the version it came from, and the encoding the body is in.
func TestWriteRangeResponse_EmitsVersionAndEntityHeaders(t *testing.T) {
	h := newResponseTestHandler(nil)

	window := []byte("0123456789")
	out := &s3.GetObjectOutput{
		ETag:               aws.String(`"ciphertext-etag"`),
		ContentType:        aws.String("text/plain"),
		VersionId:          aws.String("version-42"),
		ContentEncoding:    aws.String("gzip"),
		ContentDisposition: aws.String(`attachment; filename="x.txt"`),
		ContentLanguage:    aws.String("de-DE"),
		CacheControl:       aws.String("max-age=99"),
		ChecksumSHA256:     aws.String("AAAAAA=="),
		Metadata:           map[string]string{"user": "value", "s3ep-dek-algorithm": "aes-ctr"},
	}

	rr := httptest.NewRecorder()
	h.writeRangeResponse(rr, httptest.NewRequest(http.MethodGet, "/b/k", nil), bytes.NewReader(window), "bytes 0-9/100", int64(len(window)), out)

	require.Equal(t, http.StatusPartialContent, rr.Code)
	assert.Equal(t, "version-42", rr.Header().Get("x-amz-version-id"))
	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, `attachment; filename="x.txt"`, rr.Header().Get("Content-Disposition"))
	assert.Equal(t, "de-DE", rr.Header().Get("Content-Language"))
	assert.Equal(t, "max-age=99", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "value", rr.Header().Get("x-amz-meta-user"))
	assert.Empty(t, rr.Header().Get("x-amz-meta-s3ep-dek-algorithm"))
	assertNoChecksumHeaders(t, rr.Result().Header)
	assert.Equal(t, window, rr.Body.Bytes())
}

// A ranged read must carry the version through to the backend: without it the
// proxy would plan a window against one version and read another.
func TestHandleGetObjectRange_TheBackendGetCarriesTheVersion(t *testing.T) {
	backend := new(MockS3Backend)
	h := newEncryptingTestHandler(t, backend)

	var captured []*s3.GetObjectInput
	backend.On("GetObject", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = append(captured, args.Get(1).(*s3.GetObjectInput))
	}).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(make([]byte, 10))),
		ContentLength: aws.Int64(10),
		ContentRange:  aws.String("bytes 0-9/100"),
		Metadata:      map[string]string{"s3ep-encrypted-dek": "ZW5jcnlwdGVkLWRlaw==", "s3ep-dek-algorithm": "aes-gcm"},
	}, nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/test-bucket/test-key?versionId=version-42", nil)
	req.Header.Set("Range", "bytes=0-9")

	h.handleGetObjectRange(httptest.NewRecorder(), req, "test-bucket", "test-key", "bytes=0-9")

	require.Len(t, captured, 1, "an explicit range costs exactly one backend request")
	assert.Equal(t, "version-42", aws.ToString(captured[0].VersionId), "the backend GET dropped the version")
}
