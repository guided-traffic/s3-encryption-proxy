package storedobject

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/keyencryption"
)

func testKEK(t *testing.T) *keyencryption.AESProvider {
	t.Helper()
	raw := make([]byte, keyencryption.KEKSize)
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	kek, err := keyencryption.NewAESKeyEncryptor(raw)
	require.NoError(t, err)
	return kek.(*keyencryption.AESProvider)
}

// A client that sends x-amz-meta-s3ep-encrypted-dek must not be able to dictate
// the stored data key: the format's own value wins. The three keys below are the
// ones that collide; the fourth is inside the namespace and collides with
// nothing, which is what lets the namespace assertion fail at all - overwriting
// the collisions alone would leave it stored (ADR 0009 D6).
func TestMetadataDropsEveryUserKeyInsideTheNamespace(t *testing.T) {
	md := Metadata(DefaultPrefix, []byte("real-dek"), "real-fp", "aes", map[string]string{
		"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("attacker-dek")),
		"s3ep-kek-fingerprint": "attacker-fp",
		"s3ep-dek-algorithm":   "attacker-format",
		"s3ep-not-a-field":     "smuggled",
		"S3EP-Not-A-Field":     "smuggled in another case",
		"keep-me":              "client metadata outside the namespace",
	})

	assert.Equal(t, map[string]string{
		"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("real-dek")),
		"s3ep-kek-fingerprint": "real-fp",
		"s3ep-dek-algorithm":   dataencryption.FormatID,
		"s3ep-kek-algorithm":   "aes",
		"keep-me":              "client metadata outside the namespace",
	}, md, "the four format keys and the one key the client may keep, nothing else")
}

func TestNewKeysAnObjectThatItsMetadataOpens(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t)

	codec, md, err := New(ctx, kek, "custom-", "dir/object", map[string]string{"owner": "me"})
	require.NoError(t, err)

	assert.True(t, ClaimsFormat("custom-", md))
	assert.False(t, ClaimsFormat(DefaultPrefix, md), "the prefix is part of the key name")
	fingerprint, err := Fingerprint("custom-", md)
	require.NoError(t, err)
	assert.Equal(t, kek.Fingerprint(), fingerprint)
	assert.Equal(t, "aes", KEKAlgorithm("custom-", md))
	assert.Equal(t, map[string]string{"owner": "me"}, UserMetadata("custom-", md))

	stored, err := io.ReadAll(codec.NewEncryptReader(bytes.NewReader([]byte("hello"))))
	require.NoError(t, err)

	// The wrapped key in the metadata is the key the object was sealed under.
	wrapped, err := WrappedDEK("custom-", md)
	require.NoError(t, err)
	dek, err := kek.DecryptDEK(ctx, wrapped)
	require.NoError(t, err)
	opener, err := dataencryption.NewCodec(dek, "dir/object")
	require.NoError(t, err)
	plain, err := io.ReadAll(opener.NewReader(bytes.NewReader(stored)))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(plain))

	// One data key per object (ADR 0002 D1).
	_, other, err := New(ctx, kek, "custom-", "dir/object", nil)
	require.NoError(t, err)
	assert.NotEqual(t, md["custom-"+KeyEncryptedDEK], other["custom-"+KeyEncryptedDEK])
}

func TestGettersReportMissingAndMalformedFields(t *testing.T) {
	_, err := WrappedDEK(DefaultPrefix, map[string]string{})
	assert.ErrorIs(t, err, ErrNoWrappedDEK)
	_, err = Fingerprint(DefaultPrefix, map[string]string{})
	assert.ErrorIs(t, err, ErrNoFingerprint)
	assert.Empty(t, KEKAlgorithm(DefaultPrefix, map[string]string{}))

	for _, value := range []string{"not!base64", ""} {
		_, err = WrappedDEK(DefaultPrefix, map[string]string{"s3ep-encrypted-dek": value})
		assert.ErrorIs(t, err, ErrNoWrappedDEK, "value %q", value)
	}

	// The lookups are case-sensitive, while S3 user metadata keys are not: a
	// case-different key is invisible to the read path, so such an object is
	// refused rather than half-read.
	_, err = WrappedDEK(DefaultPrefix, map[string]string{"S3EP-encrypted-dek": "ZGVr"})
	assert.ErrorIs(t, err, ErrNoWrappedDEK)
	assert.False(t, ClaimsFormat(DefaultPrefix, map[string]string{"S3EP-dek-algorithm": dataencryption.FormatID}))
}

// The prefix is the format's namespace, and a key outside it is a client's. The
// unprefixed names are not filtered out of a client's own metadata, so reading
// them would let a client hand the read path values it chose (ADR 0009 D1).
func TestUnprefixedKeysAreNeverRead(t *testing.T) {
	md := map[string]string{
		"encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("dek")),
		"dek-algorithm":   dataencryption.FormatID,
		"kek-fingerprint": "someone-elses-fp",
		"kek-algorithm":   "aes",
	}
	assert.False(t, ClaimsFormat(DefaultPrefix, md))
	_, err := WrappedDEK(DefaultPrefix, md)
	assert.ErrorIs(t, err, ErrNoWrappedDEK)
	_, err = Fingerprint(DefaultPrefix, md)
	assert.ErrorIs(t, err, ErrNoFingerprint)

	md["s3ep-kek-fingerprint"] = "current"
	fingerprint, err := Fingerprint(DefaultPrefix, md)
	require.NoError(t, err)
	assert.Equal(t, "current", fingerprint, "the prefixed value wins")
}

func TestIsReservedIgnoresCase(t *testing.T) {
	for key, want := range map[string]bool{
		"s3ep-encrypted-dek": true,
		"S3EP-Encrypted-DEK": true,
		"S3ep-anything":      true,
		"s3ep":               false,
		"s3epx-key":          false,
		"s3ep-":              true,
		"as3ep-hmac":         false,
		" s3ep-hmac":         false,
		"owner":              false,
		"":                   false,
	} {
		assert.Equal(t, want, IsReserved(DefaultPrefix, key), "key %q", key)
	}
}

func TestUserMetadataIsNilWhenNothingIsLeft(t *testing.T) {
	assert.Nil(t, UserMetadata(DefaultPrefix, nil))
	assert.Nil(t, UserMetadata(DefaultPrefix, map[string]string{"s3ep-dek-algorithm": "x"}))
	assert.Equal(t, map[string]string{"Owner": "a"},
		UserMetadata(DefaultPrefix, map[string]string{"Owner": "a", "S3ep-Kek-Fingerprint": "b"}))
}

func TestPrefixPattern(t *testing.T) {
	for _, ok := range []string{DefaultPrefix, "mycompany-enc-", "a1b-"} {
		assert.True(t, PrefixPattern.MatchString(ok), ok)
	}
	for _, bad := range []string{"", "S3EP-", "s3ep", "ab-", "-abc-", "s3_ep-"} {
		assert.False(t, PrefixPattern.MatchString(bad), bad)
	}
}

func TestTotalFromContentRange(t *testing.T) {
	for header, want := range map[string]int64{
		"bytes 0-99/1000":     1000,
		" bytes 123-162/163 ": 163,
		"bytes 0-0/0":         0,
	} {
		got, err := TotalFromContentRange(header)
		require.NoError(t, err, header)
		assert.Equal(t, want, got, header)
	}
	for _, bad := range []string{"", "bytes 0-1/*", "bytes 0-1", "bytes 0-1/-5", "items 0-1/2", "bytes 0-1/abc"} {
		_, err := TotalFromContentRange(bad)
		assert.Error(t, err, "%q", bad)
	}
}

func TestNewReportsAWrapFailure(t *testing.T) {
	_, _, err := New(context.Background(), failingKEK{}, DefaultPrefix, "k", nil)
	assert.ErrorIs(t, err, errWrap)
}

var errWrap = errors.New("wrap failed")

type failingKEK struct{}

func (failingKEK) EncryptDEK(context.Context, []byte) ([]byte, error) { return nil, errWrap }
func (failingKEK) DecryptDEK(context.Context, []byte) ([]byte, error) { return nil, errWrap }
func (failingKEK) Name() string                                       { return "failing" }
func (failingKEK) Fingerprint() string                                { return "failing" }
