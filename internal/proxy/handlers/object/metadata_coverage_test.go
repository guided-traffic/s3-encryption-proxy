package object

import (
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
)

// ---------------------------------------------------------------------------
// Metadata filtering, version headers, entity headers and the response copy.
// These are the pieces that decide what a client is told about an object, and
// none of them depends on how the bytes are stored, so the storage-format change
// (ADR 0003) leaves this file alone.
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
	write, err := h.encryptionMgr.NewSegmentedWrite(objectKey, bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(write.Body)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext, "the fixture must not store plaintext")

	// The SDK hands metadata keys back lowercased, so a fixture that stands in
	// for the backend has to do the same.
	lowered := make(map[string]string, len(write.Metadata))
	for k, v := range write.Metadata {
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

// An empty prefix matches every key, so the namespace swallows all user
// metadata: nothing survives a GET or a HEAD, and on the way in every write is
// now refused rather than silently stripped. The value cannot be configured —
// startup refuses it (ADR 0009 D2) — and this pins what the code does if it ever
// reached the handler again.
func TestObjMiscEmptyMetadataPrefixSwallowsAllUserMetadata(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandlerWithPrefix(t, backend, "")

	assert.True(t, h.isEncryptionMetadata("owner"),
		"with an empty prefix every key counts as encryption metadata")
	assert.True(t, h.isEncryptionMetadata(""))
	assert.Nil(t, h.cleanMetadata(map[string]string{"owner": "hans", "project": "orion"}),
		"all user metadata is dropped from the response")

	// And on the way in: the write is refused instead of storing nothing.
	req := httptest.NewRequest(http.MethodPut, "/b/k", nil)
	req.Header.Set("x-amz-meta-owner", "hans")
	got, err := h.userMetadataFromRequest(req)
	assert.Nil(t, got)
	assert.Error(t, err)
}

// isEncryptionMetadata is a case-insensitive prefix test, nothing more. The
// upper-case spellings are the ones that matter: net/http canonicalises every
// request header name, so a client sending x-amz-meta-s3ep-encrypted-dek hands
// the handler the key "S3ep-Encrypted-Dek". Table-driven so the boundary cases
// are visible next to each other.
func TestObjMiscIsEncryptionMetadataBoundaries(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandler(t, backend)

	cases := map[string]bool{
		"s3ep-encrypted-dek": true,
		"s3ep-":              true,
		"s3ep":               false,
		"s3e":                false,
		"":                   false,
		"S3EP-encrypted-dek": true,
		"S3ep-Encrypted-Dek": true,
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

// A prefix the proxy cannot match its own metadata against used to disable
// decryption silently: the stored ciphertext went out as a clean 200 and the
// wrapped key went with it as an x-amz-meta- header. Under the segment chain
// that case is closed by construction — an object whose metadata the proxy does
// not recognise is not its own object, and it is refused rather than served
// (ADR 0003). Configuration validation refuses a non-lowercase prefix too, so
// this is the second lock on the same door.
func TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjMiscnewHandlerWithPrefix(t, backend, "S3EP-")

	plaintext := ObjMiscpayload(512)
	ciphertext, stored := ObjMiscstore(t, h, plaintext, "k")
	require.Contains(t, stored, "s3ep-encrypted-dek",
		"the SDK hands metadata keys back lowercased")

	ObjServeStored(backend, ciphertext, s3.GetObjectOutput{Metadata: stored})

	t.Run("GET refuses rather than serving ciphertext", func(t *testing.T) {
		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "InvalidObjectState")
		assert.NotEqual(t, ObjMiscdigest(ciphertext), ObjMiscdigest(rr.Body.Bytes()),
			"no stored byte may reach the client")
	})

	t.Run("HEAD refuses rather than leaking the wrapped key", func(t *testing.T) {
		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k", nil), "b", "k")

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Empty(t, rr.Header().Get("x-amz-meta-s3ep-encrypted-dek"),
			"the wrapped DEK must not reach the client")
		assert.Empty(t, rr.Header().Get("x-amz-meta-s3ep-kek-fingerprint"))
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
		ciphertext, stored := ObjMiscstore(t, h, ObjMiscpayload(64), "k")
		ObjServeStored(backend, ciphertext, s3.GetObjectOutput{
			VersionId: aws.String("v7"),
			Metadata:  stored,
		})

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodHead, "/b/k?versionId=v7", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		for _, call := range backend.Calls {
			if call.Method == "GetObject" {
				assert.Equal(t, "v7", aws.ToString(call.Arguments.Get(1).(*s3.GetObjectInput).VersionId),
					"the version the client asked for is the one that is read")
			}
		}
		assert.Equal(t, "v7", rr.Header().Get("x-amz-version-id"))
	})

	t.Run("GET", func(t *testing.T) {
		backend := new(MockS3Backend)
		h := ObjMiscnewHandler(t, backend)
		plaintext := ObjMiscpayload(64)
		ciphertext, stored := ObjMiscstore(t, h, plaintext, "k")
		ObjServeStored(backend, ciphertext, s3.GetObjectOutput{
			VersionId: aws.String("v7"),
			Metadata:  stored,
		})

		rr := ObjMiscdo(h, httptest.NewRequest(http.MethodGet, "/b/k?versionId=v7", nil), "b", "k")

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, ObjMiscdigest(plaintext), ObjMiscdigest(rr.Body.Bytes()))
		for _, call := range backend.Calls {
			if call.Method == "GetObject" {
				assert.Equal(t, "v7", aws.ToString(call.Arguments.Get(1).(*s3.GetObjectInput).VersionId),
					"every read of a versioned object names the version")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// writeEntityHeaders.
// ---------------------------------------------------------------------------

// The five entity headers describe the plaintext, so they survive encryption
// and a GET that drops them would contradict its own HEAD. Empty and nil values
// must not turn into empty headers.
func TestObjMiscWriteEntityHeaders(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, storedEntityHeaders{
			ContentEncoding:    aws.String("gzip"),
			ContentDisposition: aws.String(`attachment; filename="a.txt"`),
			ContentLanguage:    aws.String("de-DE"),
			CacheControl:       aws.String("max-age=60"),
			Expires:            aws.String("Wed, 21 Oct 2099 07:28:00 GMT"),
		})
		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
		assert.Equal(t, `attachment; filename="a.txt"`, rr.Header().Get("Content-Disposition"))
		assert.Equal(t, "de-DE", rr.Header().Get("Content-Language"))
		assert.Equal(t, "max-age=60", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "Wed, 21 Oct 2099 07:28:00 GMT", rr.Header().Get("Expires"))
	})

	t.Run("nil and empty are skipped", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, storedEntityHeaders{
			ContentEncoding: aws.String(""),
			CacheControl:    aws.String("no-store"),
		})
		assert.Empty(t, rr.Header().Values("Content-Encoding"))
		assert.Empty(t, rr.Header().Values("Content-Disposition"))
		assert.Empty(t, rr.Header().Values("Content-Language"))
		assert.Empty(t, rr.Header().Values("Expires"))
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	})

	t.Run("empty output writes nothing", func(t *testing.T) {
		rr := httptest.NewRecorder()
		writeEntityHeaders(rr, storedEntityHeaders{})
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
