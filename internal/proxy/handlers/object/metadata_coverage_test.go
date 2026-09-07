package object

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
)

// ---------------------------------------------------------------------------
// Metadata filtering, version headers, entity headers and the response copy.
// These are the pieces that decide what a client is told about an object, and
// none of them depends on how the bytes are stored, so ticket 013 leaves this
// file alone.
// ---------------------------------------------------------------------------

// ObjMiscdigest keeps large-payload comparisons out of the failure output.
func ObjMiscdigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ObjMiscpayload builds a deterministic payload of n bytes.
func ObjMiscpayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x2545f491)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}

// ObjMiscstore encrypts plaintext the way the write path does and returns what
// the backend would hold. The returned metadata keys are lowercased because
// that is what the AWS SDK hands back on a read: it lowercases every
// x-amz-meta-* header name while deserialising.
func ObjMiscstore(t *testing.T, h *Handler, plaintext []byte, objectKey string) ([]byte, map[string]string) {
	t.Helper()
	res, err := h.encryptionMgr.EncryptGCM(t.Context(), bufio.NewReader(bytes.NewReader(plaintext)), objectKey)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext, "the fixture must not store plaintext")

	lowered := make(map[string]string, len(res.Metadata))
	for k, v := range res.Metadata {
		lowered[strings.ToLower(k)] = v
	}
	return ciphertext, lowered
}

// ---------------------------------------------------------------------------
// cleanMetadata / isEncryptionMetadata.
// ---------------------------------------------------------------------------

// Every key carrying the configured prefix goes; everything else stays. The
// near-miss keys are the point: "s3ep" without the hyphen and "xs3ep-" are user
// metadata and must survive.
func TestObjMiscCleanMetadataStripsOnlyThePrefixedKeys(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	in := map[string]string{
		"s3ep-encrypted-dek":   "wrapped",
		"s3ep-dek-algorithm":   "aes-gcm",
		"s3ep-aes-iv":          "iv",
		"s3ep-kek-algorithm":   "aes",
		"s3ep-kek-fingerprint": "fp",
		"s3ep-hmac":            "tag",
		"s3ep-":                "bare prefix",
		"s3ep":                 "no hyphen, user metadata",
		"xs3ep-encrypted-dek":  "different prefix, user metadata",
		"s3e":                  "shorter than the prefix",
		"owner":                "hans",
		"project":              "orion",
		"":                     "empty key",
	}

	got := h.cleanMetadata(in)

	assert.Equal(t, map[string]string{
		"s3ep":                "no hyphen, user metadata",
		"xs3ep-encrypted-dek": "different prefix, user metadata",
		"s3e":                 "shorter than the prefix",
		"owner":               "hans",
		"project":             "orion",
		"":                    "empty key",
	}, got)

	for key := range got {
		assert.False(t, strings.HasPrefix(key, "s3ep-"),
			"no key carrying the prefix may survive: %q", key)
	}
	// The input is not modified in place; callers still need the real metadata.
	assert.Len(t, in, 13)
}

// nil in, nil out; and an input made only of encryption metadata collapses to
// nil rather than to an empty map, because the SDK treats the two the same.
func TestObjMiscCleanMetadataEdgeInputs(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	assert.Nil(t, h.cleanMetadata(nil))
	assert.Nil(t, h.cleanMetadata(map[string]string{}))
	assert.Nil(t, h.cleanMetadata(map[string]string{"s3ep-hmac": "tag"}))
	assert.Equal(t, map[string]string{"a": "b"}, h.cleanMetadata(map[string]string{"a": "b", "s3ep-hmac": "t"}))
}

// A custom prefix is honoured, and the default prefix is then just user
// metadata: nothing hardcodes "s3ep-" on this path.
func TestObjMiscCleanMetadataHonoursACustomPrefix(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandlerWithPrefix(t, backend, "acme-")

	got := h.cleanMetadata(map[string]string{
		"acme-encrypted-dek": "wrapped",
		"s3ep-encrypted-dek": "not the configured prefix",
		"owner":              "hans",
	})

	assert.Equal(t, map[string]string{
		"s3ep-encrypted-dek": "not the configured prefix",
		"owner":              "hans",
	}, got)
}

// DEFECT (major, reported): metadata_key_prefix is a supported configuration
// value and the empty string is explicitly allowed (internal/config accepts it
// and keeps it). isEncryptionMetadata then compares a zero-length prefix, which
// every key matches, so cleanMetadata strips ALL metadata: no user metadata
// survives a GET or a HEAD, and prepareEncryptionMetadata drops every
// x-amz-meta-* header on the way in. The configuration reads as "do not prefix"
// and behaves as "discard all metadata".
func TestObjMiscEmptyMetadataPrefixDiscardsAllUserMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandlerWithPrefix(t, backend, "")

	assert.True(t, h.isEncryptionMetadata("owner"),
		"with an empty prefix every key counts as encryption metadata")
	assert.True(t, h.isEncryptionMetadata(""))
	assert.Nil(t, h.cleanMetadata(map[string]string{"owner": "hans", "project": "orion"}),
		"all user metadata is dropped from the response")

	// And on the way in: nothing a client sends is stored.
	req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
	req.Header.Set("x-amz-meta-owner", "hans")
	got := h.prepareEncryptionMetadata(req, ObjMiscemptyEncryptionResult())
	assert.Empty(t, got, "user metadata never reaches the backend either")
}

// isEncryptionMetadata is a prefix test, nothing more. Table-driven so the
// boundary cases are visible next to each other.
func TestObjMiscIsEncryptionMetadataBoundaries(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	cases := map[string]bool{
		"s3ep-encrypted-dek": true,
		"s3ep-":              true,
		"s3ep":               false,
		"s3e":                false,
		"":                   false,
		"S3EP-encrypted-dek": false,
		"S3ep-Encrypted-Dek": false,
		"as3ep-hmac":         false,
		" s3ep-hmac":         false,
	}

	for key, want := range cases {
		t.Run(strconv.Quote(key), func(t *testing.T) {
			assert.Equal(t, want, h.isEncryptionMetadata(key))
		})
	}
}

// ---------------------------------------------------------------------------
// The case-sensitivity of the filter, seen from the client.
// ---------------------------------------------------------------------------

// DEFECT (major, reported): the prefix comparison is case-sensitive, while S3
// metadata keys are case-insensitive and the AWS SDK lowercases every key it
// reads back. Configure metadata_key_prefix with any uppercase character and
// two things follow at once, with no warning from config validation:
//
//   - GET no longer recognises its own encryption metadata, so the stored
//     CIPHERTEXT is served to the client as a clean 200.
//   - HEAD and GET stop filtering it, so the wrapped DEK, the KEK fingerprint
//     and the HMAC are handed to every client as x-amz-meta-* headers.
//
// Pinned here as the current behaviour; the fix is to compare case-insensitively
// (or to reject a non-lowercase prefix at load time).
func TestObjMiscUppercaseMetadataPrefixDisablesDecryptionAndLeaksMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandlerWithPrefix(t, backend, "S3EP-")

	plaintext := ObjMiscpayload(512)
	ciphertext, stored := ObjMiscstore(t, h, plaintext, "k")
	require.Contains(t, stored, "s3ep-encrypted-dek",
		"the SDK hands metadata keys back lowercased")

	t.Run("GET serves the ciphertext with 200", func(t *testing.T) {
		backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(ciphertext)),
			ContentLength: aws.Int64(int64(len(ciphertext))),
			Metadata:      stored,
		}, nil).Once()

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, ObjMiscdigest(ciphertext), ObjMiscdigest(rr.Body.Bytes()),
			"the client is handed ciphertext and told it is the object")
		assert.NotEqual(t, ObjMiscdigest(plaintext), ObjMiscdigest(rr.Body.Bytes()))
	})

	t.Run("HEAD leaks the encryption metadata", func(t *testing.T) {
		backend.On("HeadObject", mock.Anything, mock.Anything).Return(&s3.HeadObjectOutput{
			ContentLength: aws.Int64(int64(len(ciphertext))),
			Metadata:      stored,
		}, nil).Once()

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("x-amz-meta-s3ep-encrypted-dek"),
			"the wrapped DEK reaches the client")
		assert.NotEmpty(t, rr.Header().Get("x-amz-meta-s3ep-kek-fingerprint"))
	})
}

// With the default lowercase prefix none of that happens: the metadata is
// filtered and the plaintext comes back. This is the control for the test above.
func TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	plaintext := ObjMiscpayload(512)
	ciphertext, stored := ObjMiscstore(t, h, plaintext, "k")
	stored["owner"] = "hans"

	backend.On("GetObject", mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(ciphertext)),
		ContentLength: aws.Int64(int64(len(ciphertext))),
		Metadata:      stored,
	}, nil)

	rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ObjMiscdigest(plaintext), ObjMiscdigest(rr.Body.Bytes()))
	assert.Equal(t, "hans", rr.Header().Get("x-amz-meta-owner"))
	for _, leaked := range []string{
		"x-amz-meta-s3ep-encrypted-dek",
		"x-amz-meta-s3ep-dek-algorithm",
		"x-amz-meta-s3ep-kek-fingerprint",
		"x-amz-meta-s3ep-hmac",
		"x-amz-meta-s3ep-aes-iv",
	} {
		assert.Empty(t, rr.Header().Get(leaked), "%s must never reach the client", leaked)
	}
}

// ---------------------------------------------------------------------------
// MetadataHandler.FilterEncryptionMetadata.
// ---------------------------------------------------------------------------

// DEFECT (minor, reported): MetadataHandler is constructed by NewHandler and
// exposed by GetMetadataHandler, but no route and no handler calls
// FilterEncryptionMetadata, so this is a second, divergent copy of the filter
// that never runs. It differs from the live one in two ways, both pinned here:
// an empty configured prefix falls back to "s3ep-" instead of matching
// everything, and an all-encryption input returns an empty map rather than nil.
func TestObjMiscFilterEncryptionMetadataDivergesFromTheLiveFilter(t *testing.T) {
	backend := new(MockS3Backend)

	t.Run("default prefix", func(t *testing.T) {
		h := ObjMiscnewHandler(t, backend).GetMetadataHandler()
		got := h.FilterEncryptionMetadata(map[string]string{
			"s3ep-encrypted-dek": "wrapped",
			"s3ep":               "user metadata",
			"owner":              "hans",
		})
		assert.Equal(t, map[string]string{"s3ep": "user metadata", "owner": "hans"}, got)
	})

	t.Run("custom prefix", func(t *testing.T) {
		h := ObjMiscnewHandlerWithPrefix(t, backend, "acme-").GetMetadataHandler()
		got := h.FilterEncryptionMetadata(map[string]string{
			"acme-hmac":          "tag",
			"s3ep-encrypted-dek": "not the configured prefix",
		})
		assert.Equal(t, map[string]string{"s3ep-encrypted-dek": "not the configured prefix"}, got)
	})

	t.Run("empty prefix falls back to s3ep- instead of matching everything", func(t *testing.T) {
		live := ObjMiscnewHandlerWithPrefix(t, backend, "")
		dead := live.GetMetadataHandler()

		in := map[string]string{"owner": "hans", "s3ep-hmac": "tag"}
		assert.Equal(t, map[string]string{"owner": "hans"}, dead.FilterEncryptionMetadata(in))
		assert.Nil(t, live.cleanMetadata(in), "the live filter drops everything for the same config")
	})

	t.Run("nil and all-encryption inputs", func(t *testing.T) {
		h := ObjMiscnewHandler(t, backend).GetMetadataHandler()
		assert.Equal(t, map[string]string{}, h.FilterEncryptionMetadata(nil))
		assert.Equal(t, map[string]string{},
			h.FilterEncryptionMetadata(map[string]string{"s3ep-hmac": "tag"}))
	})
}

// ---------------------------------------------------------------------------
// objectVersionID and writeVersionHeaders.
// ---------------------------------------------------------------------------

func TestObjMiscObjectVersionIDReadsTheQueryParameter(t *testing.T) {
	cases := map[string]struct {
		url  string
		want *string
	}{
		"absent":         {"/b/k", nil},
		"empty":          {"/b/k?versionId=", nil},
		"present":        {"/b/k?versionId=v1", aws.String("v1")},
		"escaped":        {"/b/k?versionId=a%20b", aws.String("a b")},
		"wrong_case_key": {"/b/k?versionid=v1", nil},
		"with_others":    {"/b/k?foo=1&versionId=v2&bar=3", aws.String("v2")},
		"repeated":       {"/b/k?versionId=first&versionId=second", aws.String("first")},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := objectVersionID(httptest.NewRequest(http.MethodGet, tc.url, nil))
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

func TestObjMiscWriteVersionHeaders(t *testing.T) {
	cases := map[string]struct {
		versionID    *string
		deleteMarker *bool
		wantVersion  string
		wantMarker   string
	}{
		"nothing":            {nil, nil, "", ""},
		"empty_version":      {aws.String(""), nil, "", ""},
		"version_only":       {aws.String("v1"), nil, "v1", ""},
		"marker_false":       {aws.String("v1"), aws.Bool(false), "v1", ""},
		"marker_true":        {aws.String("v1"), aws.Bool(true), "v1", "true"},
		"marker_without_ver": {nil, aws.Bool(true), "", "true"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeVersionHeaders(rr, tc.versionID, tc.deleteMarker)
			assert.Equal(t, tc.wantVersion, rr.Header().Get("x-amz-version-id"))
			assert.Equal(t, tc.wantMarker, rr.Header().Get("x-amz-delete-marker"))
		})
	}
}

// The versionId a client asks for has to reach the backend on every method that
// takes one, and the version the backend reports has to come back.
func TestObjMiscVersionIDTravelsBothWaysOnDelete(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	var captured *s3.DeleteObjectInput
	backend.On("DeleteObject", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.DeleteObjectInput) }).
		Return(&s3.DeleteObjectOutput{
			VersionId:    aws.String("dm-1"),
			DeleteMarker: aws.Bool(true),
		}, nil)

	rr := ObjMiscdo(h, httptest.NewRequest(http.MethodDelete, "/b/k?versionId=v7", nil), "b", "k")

	assert.Equal(t, http.StatusNoContent, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "v7", aws.ToString(captured.VersionId))
	assert.Equal(t, "dm-1", rr.Header().Get("x-amz-version-id"))
	assert.Equal(t, "true", rr.Header().Get("x-amz-delete-marker"))
}

func TestObjMiscVersionIDReachesHeadAndGet(t *testing.T) {
	t.Run("HEAD", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		var captured *s3.HeadObjectInput
		backend.On("HeadObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.HeadObjectInput) }).
			Return(&s3.HeadObjectOutput{VersionId: aws.String("v7")}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k?versionId=v7", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, captured)
		assert.Equal(t, "v7", aws.ToString(captured.VersionId))
		assert.Equal(t, "v7", rr.Header().Get("x-amz-version-id"))
	})

	t.Run("GET", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		var captured *s3.GetObjectInput
		backend.On("GetObject", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*s3.GetObjectInput) }).
			Return(&s3.GetObjectOutput{
				Body:          io.NopCloser(strings.NewReader("body")),
				ContentLength: aws.Int64(4),
				VersionId:     aws.String("v7"),
			}, nil)

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?versionId=v7", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, captured)
		assert.Equal(t, "v7", aws.ToString(captured.VersionId))
	})
}

// ---------------------------------------------------------------------------
// writeEntityHeaders.
// ---------------------------------------------------------------------------

// The four entity headers describe the plaintext, so they survive encryption
// and a GET that drops them would contradict its own HEAD. Empty and nil values
// must not turn into empty headers.
func TestObjMiscWriteEntityHeaders(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, &s3.GetObjectOutput{
			ContentEncoding:    aws.String("gzip"),
			ContentDisposition: aws.String(`attachment; filename="a.txt"`),
			ContentLanguage:    aws.String("de-DE"),
			CacheControl:       aws.String("max-age=60"),
		})
		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
		assert.Equal(t, `attachment; filename="a.txt"`, rr.Header().Get("Content-Disposition"))
		assert.Equal(t, "de-DE", rr.Header().Get("Content-Language"))
		assert.Equal(t, "max-age=60", rr.Header().Get("Cache-Control"))
	})

	t.Run("nil and empty are skipped", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, &s3.GetObjectOutput{
			ContentEncoding: aws.String(""),
			CacheControl:    aws.String("no-store"),
		})
		assert.Empty(t, rr.Header().Values("Content-Encoding"))
		assert.Empty(t, rr.Header().Values("Content-Disposition"))
		assert.Empty(t, rr.Header().Values("Content-Language"))
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	})

	t.Run("empty output writes nothing", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, &s3.GetObjectOutput{})
		assert.Empty(t, rr.Header())
	})
}

// ---------------------------------------------------------------------------
// copyWithPooledBuffer.
// ---------------------------------------------------------------------------

// The pooled buffer must not change what is copied, at any size around the
// buffer boundary, and the pool must be safe to reuse across calls.
func TestObjMiscCopyWithPooledBufferIsByteExact(t *testing.T) {
	for _, size := range []int{
		0, 1, 4096,
		getResponseBufferSize - 1, getResponseBufferSize, getResponseBufferSize + 1,
		3*getResponseBufferSize + 7,
	} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			src := ObjMiscpayload(size)
			var dst bytes.Buffer

			n, err := copyWithPooledBuffer(&dst, bytes.NewReader(src))

			require.NoError(t, err)
			assert.Equal(t, int64(size), n)
			assert.Equal(t, ObjMiscdigest(src), ObjMiscdigest(dst.Bytes()))
		})
	}
}

// A read failure is reported with what was copied so far, not swallowed.
func TestObjMiscCopyWithPooledBufferPropagatesReadErrors(t *testing.T) {
	var dst bytes.Buffer
	n, err := copyWithPooledBuffer(&dst, &ObjMiscbrokenReader{prefix: []byte("half")})

	require.Error(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, "half", dst.String())
}

// ObjMiscshortWriter accepts only a prefix, the way a closed connection does.
type ObjMiscshortWriter struct {
	limit int
	got   []byte
}

func (w *ObjMiscshortWriter) Write(p []byte) (int, error) {
	room := w.limit - len(w.got)
	if room <= 0 {
		return 0, errors.New("connection closed")
	}
	if len(p) > room {
		w.got = append(w.got, p[:room]...)
		return room, io.ErrShortWrite
	}
	w.got = append(w.got, p...)
	return len(p), nil
}

func TestObjMiscCopyWithPooledBufferPropagatesWriteErrors(t *testing.T) {
	w := &ObjMiscshortWriter{limit: 10}
	n, err := copyWithPooledBuffer(w, bytes.NewReader(ObjMiscpayload(64*1024)))

	require.Error(t, err)
	assert.Equal(t, int64(10), n)
	assert.Len(t, w.got, 10)
}

// ---------------------------------------------------------------------------
// Small shared fixture.
// ---------------------------------------------------------------------------

// ObjMiscemptyEncryptionResult is an encryption result that contributes no
// metadata of its own, so a test sees only what came from the request headers.
func ObjMiscemptyEncryptionResult() *orchestration.EncryptionResult {
	return &orchestration.EncryptionResult{Metadata: map[string]string{}}
}
