package factory

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// FacTestAESKeyB64 is a base64-encoded 32-byte AES-256 KEK used across these tests.
const FacTestAESKeyB64 = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// FacOtherAESKeyB64 is a second, different 32-byte AES-256 KEK.
const FacOtherAESKeyB64 = "paUqdsB3Vq+6sr7QE2iFdfm08ZiNrp6Jyfli4ssWMdo="

var ()

// FacFactoryWithAES builds a factory with a single registered AES key encryptor
// and returns both, so tests can address it by fingerprint.
func FacFactoryWithAES(t *testing.T, keyB64 string) (*Factory, encryption.KeyEncryptor) {
	t.Helper()

	f := NewFactory()
	keyEncryptor, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": keyB64,
	})
	require.NoError(t, err)
	f.RegisterKeyEncryptor(keyEncryptor)
	return f, keyEncryptor
}

// FacStubKeyEncryptor is a KeyEncryptor implementation that is not one of the
// concrete provider types the factory knows about. It exercises the "unknown"
// branch of GetRegisteredProviderInfo.
type FacStubKeyEncryptor struct {
	fingerprint string
}

func (s *FacStubKeyEncryptor) EncryptDEK(_ context.Context, dek []byte) ([]byte, error) {
	return dek, nil
}

func (s *FacStubKeyEncryptor) DecryptDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	return encryptedDEK, nil
}

func (s *FacStubKeyEncryptor) Name() string { return "stub" }

func (s *FacStubKeyEncryptor) Fingerprint() string { return s.fingerprint }

// FacDigest returns the hex SHA-256 digest of b, so large payloads are compared
// by digest rather than by dumping bytes.
func FacDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FacReadAll drains a reader and fails the test on error.
func FacReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return data
}

func TestFacGetKeyEncryptor(t *testing.T) {
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	t.Run("returns the registered encryptor for a known fingerprint", func(t *testing.T) {
		got, err := f.GetKeyEncryptor(keyEncryptor.Fingerprint())
		require.NoError(t, err)
		assert.Same(t, keyEncryptor, got)
		assert.Equal(t, "aes", got.Name())
	})

	t.Run("unknown fingerprint reports the fingerprint it looked for", func(t *testing.T) {
		got, err := f.GetKeyEncryptor("deadbeef")
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "deadbeef")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("empty fingerprint on an empty factory fails", func(t *testing.T) {
		got, err := NewFactory().GetKeyEncryptor("")
		require.Error(t, err)
		assert.Nil(t, got)
	})
}

func TestFacCreateKeyEncryptorFromConfigTypes(t *testing.T) {
	f := NewFactory()

	tests := []struct {
		name     string
		keyType  KeyEncryptionType
		config   map[string]interface{}
		wantErr  string
		wantName string
	}{
		{
			name:     "aes from base64 aes_key",
			keyType:  KeyEncryptionTypeAES,
			config:   map[string]interface{}{"aes_key": FacTestAESKeyB64},
			wantName: "aes",
		},
		{
			name:     "aes from raw kek bytes",
			keyType:  KeyEncryptionTypeAES,
			config:   map[string]interface{}{"kek": bytes.Repeat([]byte{0x2a}, 32)},
			wantName: "aes",
		},
		{
			name:    "aes kek of wrong go type is rejected",
			keyType: KeyEncryptionTypeAES,
			config:  map[string]interface{}{"kek": "not-a-byte-slice"},
			wantErr: "kek must be []byte for AES key encryptor",
		},
		{
			name:    "aes kek with wrong length is rejected",
			keyType: KeyEncryptionTypeAES,
			config:  map[string]interface{}{"kek": bytes.Repeat([]byte{0x2a}, 16)},
			wantErr: "must be exactly 32 bytes",
		},
		{
			name:    "aes without any key material is rejected",
			keyType: KeyEncryptionTypeAES,
			config:  map[string]interface{}{},
			wantErr: "missing 'aes_key' in configuration",
		},
		{
			name:    "aes with nil config is rejected",
			keyType: KeyEncryptionTypeAES,
			config:  nil,
			wantErr: "missing 'aes_key' in configuration",
		},
		{
			name:     "none ignores its config",
			keyType:  KeyEncryptionTypeNone,
			config:   map[string]interface{}{"anything": "ignored"},
			wantName: "none",
		},
		{
			name:     "none accepts a nil config",
			keyType:  KeyEncryptionTypeNone,
			config:   nil,
			wantName: "none",
		},
		{
			name:    "tink is not implemented",
			keyType: KeyEncryptionTypeTink,
			config:  map[string]interface{}{"key_uri": "gcp-kms://whatever"},
			wantErr: "tink key encryption is not yet implemented",
		},
		{
			name:    "unknown type",
			keyType: KeyEncryptionType("chacha20"),
			config:  map[string]interface{}{},
			wantErr: "unsupported key encryption type: chacha20",
		},
		{
			name:    "empty type",
			keyType: KeyEncryptionType(""),
			config:  map[string]interface{}{},
			wantErr: "unsupported key encryption type: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyEncryptor, err := f.CreateKeyEncryptorFromConfig(tt.keyType, tt.config)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Nil(t, keyEncryptor)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, keyEncryptor)
			assert.Equal(t, tt.wantName, keyEncryptor.Name())
			assert.NotEmpty(t, keyEncryptor.Fingerprint())

			// A freshly created encryptor must be able to protect and recover a DEK.
			dek := bytes.Repeat([]byte{0x11}, 32)
			encryptedDEK, err := keyEncryptor.EncryptDEK(context.Background(), dek)
			require.NoError(t, err)
			recovered, err := keyEncryptor.DecryptDEK(context.Background(), encryptedDEK)
			require.NoError(t, err)
			assert.Equal(t, dek, recovered)
		})
	}
}

func TestFacCreateAESKeyEncryptorKEKPathMatchesBase64Path(t *testing.T) {
	f := NewFactory()

	rawKEK, err := base64.StdEncoding.DecodeString(FacTestAESKeyB64)
	require.NoError(t, err)
	require.Len(t, rawKEK, 32)

	fromBytes, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"kek": rawKEK,
	})
	require.NoError(t, err)

	fromBase64, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacTestAESKeyB64,
	})
	require.NoError(t, err)

	// Both construction paths must yield the same KEK identity, otherwise objects
	// written through one config style could not be read back through the other.
	assert.Equal(t, fromBase64.Fingerprint(), fromBytes.Fingerprint())

	// The "kek" entry wins over "aes_key" when both are present.
	otherKEK := bytes.Repeat([]byte{0x7f}, 32)
	mixed, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"kek":     otherKEK,
		"aes_key": FacTestAESKeyB64,
	})
	require.NoError(t, err)
	assert.NotEqual(t, fromBase64.Fingerprint(), mixed.Fingerprint())

	// The fingerprint is derived from the key, never a hash of it (ADR 0004).
	rawHash := sha256.Sum256(otherKEK)
	assert.NotEqual(t, hex.EncodeToString(rawHash[:]), mixed.Fingerprint())
	assert.Len(t, mixed.Fingerprint(), 64)
}

func TestFacCreateEnvelopeEncryptorUnknownFingerprint(t *testing.T) {
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	for _, contentType := range []ContentType{ContentTypeWhole, ContentTypeMultipart} {
		t.Run(string(contentType), func(t *testing.T) {
			envelopeEncryptor, err := f.CreateEnvelopeEncryptor(contentType, "no-such-fingerprint", "s3ep-")
			require.Error(t, err)
			assert.Nil(t, envelopeEncryptor)
			assert.Contains(t, err.Error(), "no-such-fingerprint")
			assert.Contains(t, err.Error(), "not found")
		})
	}

	t.Run("unknown content type is rejected before anything is built", func(t *testing.T) {
		envelopeEncryptor, err := f.CreateEnvelopeEncryptor(ContentType("sideways"), keyEncryptor.Fingerprint(), "s3ep-")
		require.Error(t, err)
		assert.Nil(t, envelopeEncryptor)
		assert.Contains(t, err.Error(), "unsupported content type: sideways")
	})

	t.Run("empty content type is rejected", func(t *testing.T) {
		envelopeEncryptor, err := f.CreateEnvelopeEncryptor(ContentType(""), keyEncryptor.Fingerprint(), "s3ep-")
		require.Error(t, err)
		assert.Nil(t, envelopeEncryptor)
		assert.Contains(t, err.Error(), "unsupported content type")
	})
}

func TestFacCreateEnvelopeEncryptorRoundTrip(t *testing.T) {
	ctx := context.Background()
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	plaintext := bytes.Repeat([]byte("s3-encryption-proxy payload 0123456789"), 500)
	plaintextDigest := FacDigest(plaintext)
	associatedData := []byte("bucket/object-key")

	tests := []struct {
		name          string
		contentType   ContentType
		wantAlgorithm string
		// GCM prepends the nonce and appends the tag; CTR is length preserving.
		wantOverhead int
		// GCM extracts its nonce from the ciphertext prefix, so the decrypt call
		// receives nil; CTR needs the IV that the factory stored in metadata.
		ivFromMetadata bool
	}{
		{
			name:           "whole objects use authenticated AES-GCM",
			contentType:    ContentTypeWhole,
			wantAlgorithm:  "aes-gcm",
			wantOverhead:   12 + 16,
			ivFromMetadata: false,
		},
		{
			name:           "multipart objects use streaming AES-CTR",
			contentType:    ContentTypeMultipart,
			wantAlgorithm:  "aes-ctr",
			wantOverhead:   0,
			ivFromMetadata: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopeEncryptor, err := f.CreateEnvelopeEncryptor(tt.contentType, keyEncryptor.Fingerprint(), "s3ep-")
			require.NoError(t, err)
			require.NotNil(t, envelopeEncryptor)
			assert.Equal(t, keyEncryptor.Fingerprint(), envelopeEncryptor.Fingerprint())

			encryptedReader, encryptedDEK, metadata, err := envelopeEncryptor.EncryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader(plaintext)), associatedData)
			require.NoError(t, err)
			ciphertext := FacReadAll(t, encryptedReader)

			// Data must actually be encrypted at rest.
			assert.NotEqual(t, plaintextDigest, FacDigest(ciphertext))
			assert.False(t, bytes.Contains(ciphertext, []byte("s3-encryption-proxy payload")),
				"plaintext marker must not survive into the ciphertext")
			assert.Len(t, ciphertext, len(plaintext)+tt.wantOverhead)

			// Metadata must carry exactly what the decrypt side needs, under the prefix.
			assert.Equal(t, tt.wantAlgorithm, metadata["s3ep-dek-algorithm"])
			assert.Equal(t, "aes", metadata["s3ep-kek-algorithm"])
			assert.Equal(t, keyEncryptor.Fingerprint(), metadata["s3ep-kek-fingerprint"])
			assert.Equal(t, base64.StdEncoding.EncodeToString(encryptedDEK), metadata["s3ep-encrypted-dek"])
			assert.NotEmpty(t, encryptedDEK)
			require.Contains(t, metadata, "s3ep-aes-iv")

			iv, err := base64.StdEncoding.DecodeString(metadata["s3ep-aes-iv"])
			require.NoError(t, err)
			assert.NotEmpty(t, iv)

			var decryptIV []byte
			if tt.ivFromMetadata {
				decryptIV = iv
			}

			decryptedReader, err := envelopeEncryptor.DecryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, decryptIV, associatedData)
			require.NoError(t, err)
			assert.Equal(t, plaintextDigest, FacDigest(FacReadAll(t, decryptedReader)))
		})
	}
}

func TestFacCreateEnvelopeEncryptorMetadataPrefixIsHonoured(t *testing.T) {
	ctx := context.Background()
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	for _, prefix := range []string{"s3ep-", "custom_", ""} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			envelopeEncryptor, err := f.CreateEnvelopeEncryptor(ContentTypeWhole, keyEncryptor.Fingerprint(), prefix)
			require.NoError(t, err)

			_, _, metadata, err := envelopeEncryptor.EncryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)
			require.NoError(t, err)

			for _, field := range []string{"dek-algorithm", "encrypted-dek", "kek-algorithm", "kek-fingerprint", "aes-iv"} {
				assert.Contains(t, metadata, prefix+field)
			}
			assert.Len(t, metadata, 5, "only the five allowed metadata fields may be emitted")
		})
	}
}

func TestFacEnvelopeGCMDetectsTampering(t *testing.T) {
	ctx := context.Background()
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	envelopeEncryptor, err := f.CreateEnvelopeEncryptor(ContentTypeWhole, keyEncryptor.Fingerprint(), "s3ep-")
	require.NoError(t, err)

	plaintext := []byte("integrity matters for whole objects")
	associatedData := []byte("bucket/object-key")

	encryptedReader, encryptedDEK, _, err := envelopeEncryptor.EncryptDataStream(
		ctx, bufio.NewReader(bytes.NewReader(plaintext)), associatedData)
	require.NoError(t, err)
	ciphertext := FacReadAll(t, encryptedReader)
	require.Greater(t, len(ciphertext), 16)

	t.Run("flipped ciphertext bit fails the GCM tag check", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertext...)
		tampered[len(tampered)-17] ^= 0x01 // last plaintext byte, before the 16-byte tag

		decryptedReader, err := envelopeEncryptor.DecryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(tampered)), encryptedDEK, nil, associatedData)
		require.Error(t, err)
		assert.Nil(t, decryptedReader)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("truncated ciphertext is rejected", func(t *testing.T) {
		decryptedReader, err := envelopeEncryptor.DecryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(ciphertext[:8])), encryptedDEK, nil, associatedData)
		require.Error(t, err)
		assert.Nil(t, decryptedReader)
	})

	t.Run("wrong associated data is rejected", func(t *testing.T) {
		decryptedReader, err := envelopeEncryptor.DecryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, []byte("bucket/other-key"))
		require.Error(t, err)
		assert.Nil(t, decryptedReader)
	})
}

func TestFacEnvelopeWrongKEKCannotRecoverPlaintext(t *testing.T) {
	ctx := context.Background()

	writeFactory, writeKey := FacFactoryWithAES(t, FacTestAESKeyB64)
	readFactory, readKey := FacFactoryWithAES(t, FacOtherAESKeyB64)
	require.NotEqual(t, writeKey.Fingerprint(), readKey.Fingerprint())

	plaintext := bytes.Repeat([]byte("confidential"), 64)

	t.Run("GCM fails closed", func(t *testing.T) {
		writer, err := writeFactory.CreateEnvelopeEncryptor(ContentTypeWhole, writeKey.Fingerprint(), "s3ep-")
		require.NoError(t, err)
		encryptedReader, encryptedDEK, _, err := writer.EncryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(plaintext)), nil)
		require.NoError(t, err)
		ciphertext := FacReadAll(t, encryptedReader)

		reader, err := readFactory.CreateEnvelopeEncryptor(ContentTypeWhole, readKey.Fingerprint(), "s3ep-")
		require.NoError(t, err)
		decryptedReader, err := reader.DecryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, nil)
		require.Error(t, err)
		assert.Nil(t, decryptedReader)
	})

	t.Run("CTR fails closed at the wrap", func(t *testing.T) {
		writer, err := writeFactory.CreateEnvelopeEncryptor(ContentTypeMultipart, writeKey.Fingerprint(), "s3ep-")
		require.NoError(t, err)
		encryptedReader, encryptedDEK, metadata, err := writer.EncryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(plaintext)), nil)
		require.NoError(t, err)
		ciphertext := FacReadAll(t, encryptedReader)
		iv, err := base64.StdEncoding.DecodeString(metadata["s3ep-aes-iv"])
		require.NoError(t, err)

		reader, err := readFactory.CreateEnvelopeEncryptor(ContentTypeMultipart, readKey.Fingerprint(), "s3ep-")
		require.NoError(t, err)
		decryptedReader, err := reader.DecryptDataStream(
			ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, iv, nil)
		// The cipher below is unauthenticated, but the wrap above it is not: a
		// foreign KEK is caught while unwrapping, so no garbage stream is ever
		// handed out (ADR 0004).
		require.Error(t, err)
		assert.ErrorIs(t, err, keyencryption.ErrWrappedDEKAuth)
		assert.Nil(t, decryptedReader)
	})
}

func TestFacEnvelopeWithNoneKEKStillEncryptsData(t *testing.T) {
	ctx := context.Background()

	f := NewFactory()
	noneKey, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeNone, nil)
	require.NoError(t, err)
	f.RegisterKeyEncryptor(noneKey)

	envelopeEncryptor, err := f.CreateEnvelopeEncryptor(ContentTypeWhole, noneKey.Fingerprint(), "s3ep-")
	require.NoError(t, err)

	plaintext := []byte("none KEK protects only the DEK, not the data path")
	encryptedReader, _, metadata, err := envelopeEncryptor.EncryptDataStream(
		ctx, bufio.NewReader(bytes.NewReader(plaintext)), nil)
	require.NoError(t, err)
	ciphertext := FacReadAll(t, encryptedReader)

	assert.Equal(t, "none", metadata["s3ep-kek-algorithm"])
	assert.Equal(t, "none-provider-fingerprint", metadata["s3ep-kek-fingerprint"])
	assert.NotEqual(t, FacDigest(plaintext), FacDigest(ciphertext))

	// The none KEK stores the DEK verbatim in metadata: data is still ciphertext,
	// but anyone holding the metadata holds the key.
	// The metadata value is the canonical wrapped DEK: it is what the decrypt
	// path reads back from S3, so the round trip is asserted against it.
	storedDEK, err := base64.StdEncoding.DecodeString(metadata["s3ep-encrypted-dek"])
	require.NoError(t, err)
	assert.Len(t, storedDEK, 32)

	decryptedReader, err := envelopeEncryptor.DecryptDataStream(
		ctx, bufio.NewReader(bytes.NewReader(ciphertext)), storedDEK, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, FacDigest(plaintext), FacDigest(FacReadAll(t, decryptedReader)))
}

func TestFacGetRegisteredProviderInfo(t *testing.T) {
	f := NewFactory()
	assert.Empty(t, f.GetRegisteredProviderInfo(), "a fresh factory registers nothing")

	aesKey, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacTestAESKeyB64,
	})
	require.NoError(t, err)
	noneKey, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeNone, nil)
	require.NoError(t, err)
	stubKey := &FacStubKeyEncryptor{fingerprint: "stub-fingerprint"}

	f.RegisterKeyEncryptor(aesKey)
	f.RegisterKeyEncryptor(noneKey)
	f.RegisterKeyEncryptor(stubKey)

	infos := f.GetRegisteredProviderInfo()
	require.Len(t, infos, 3)

	byFingerprint := make(map[string]string, len(infos))
	for _, info := range infos {
		byFingerprint[info.Fingerprint] = info.Type
	}

	assert.Equal(t, "aes", byFingerprint[aesKey.Fingerprint()])
	assert.Equal(t, "none", byFingerprint[noneKey.Fingerprint()])
	assert.Equal(t, "unknown", byFingerprint["stub-fingerprint"],
		"a KeyEncryptor the factory does not know about is reported as unknown")

	// The plain fingerprint list must agree with the detailed one.
	fingerprints := f.GetRegisteredKeyEncryptors()
	assert.Len(t, fingerprints, 3)
	for fingerprint := range byFingerprint {
		assert.Contains(t, fingerprints, fingerprint)
	}
}

func TestFacRegisterKeyEncryptorKeysByFingerprint(t *testing.T) {
	f := NewFactory()

	first, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacTestAESKeyB64,
	})
	require.NoError(t, err)
	second, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacTestAESKeyB64,
	})
	require.NoError(t, err)
	require.Equal(t, first.Fingerprint(), second.Fingerprint())

	f.RegisterKeyEncryptor(first)
	f.RegisterKeyEncryptor(second)

	// Same key material means the same fingerprint, so the second registration
	// replaces the first instead of adding a duplicate slot.
	assert.Len(t, f.GetRegisteredKeyEncryptors(), 1)
	got, err := f.GetKeyEncryptor(first.Fingerprint())
	require.NoError(t, err)
	assert.Same(t, second, got)

	// Registering a genuinely different key adds a second entry.
	other, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacOtherAESKeyB64,
	})
	require.NoError(t, err)
	f.RegisterKeyEncryptor(other)
	assert.Len(t, f.GetRegisteredKeyEncryptors(), 2)
}

func TestFacDetermineContentTypeBoundaries(t *testing.T) {
	tests := []struct {
		name            string
		httpContentType string
		contentLength   int64
		isMultipart     bool
		threshold       int64
		expected        ContentType
	}{
		{
			name:            "unknown content length falls back to whole",
			httpContentType: "application/octet-stream",
			contentLength:   -1,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeWhole,
		},
		{
			name:            "unknown content length on a multipart part still streams",
			httpContentType: "application/octet-stream",
			contentLength:   -1,
			isMultipart:     true,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeMultipart,
		},
		{
			name:            "zero threshold streams even an empty body",
			httpContentType: "application/octet-stream",
			contentLength:   0,
			threshold:       0,
			expected:        ContentTypeMultipart,
		},
		{
			name:            "forced GCM beats a large body",
			httpContentType: ForceAESGCMContentType,
			contentLength:   1 << 40,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeWhole,
		},
		{
			name:            "forced CTR beats an empty body",
			httpContentType: ForceAESCTRContentType,
			contentLength:   0,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeMultipart,
		},
		{
			name:            "forcing header is matched exactly, not by prefix",
			httpContentType: ForceAESCTRContentType + "; charset=utf-8",
			contentLength:   1024,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeWhole,
		},
		{
			name:            "one byte below the configured threshold",
			httpContentType: "application/octet-stream",
			contentLength:   5*1024*1024 - 1,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeWhole,
		},
		{
			name:            "exactly at the configured threshold",
			httpContentType: "application/octet-stream",
			contentLength:   5 * 1024 * 1024,
			threshold:       5 * 1024 * 1024,
			expected:        ContentTypeMultipart,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineContentTypeFromHTTPContentType(tt.httpContentType, tt.contentLength, tt.isMultipart, tt.threshold)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFacContentTypeSelectsMatchingDataEncryptor(t *testing.T) {
	ctx := context.Background()
	f, keyEncryptor := FacFactoryWithAES(t, FacTestAESKeyB64)

	const threshold = 5 * 1024 * 1024

	// The decision function and the factory must agree: whatever ContentType the
	// header/size logic returns has to be constructible and must produce the
	// algorithm that content type promises.
	cases := []struct {
		name            string
		httpContentType string
		contentLength   int64
		isMultipart     bool
		wantAlgorithm   string
	}{
		{"small single part", "application/octet-stream", 1024, false, "aes-gcm"},
		{"large single part", "application/octet-stream", 1 << 30, false, "aes-ctr"},
		{"multipart part", "application/octet-stream", 1024, true, "aes-ctr"},
		{"forced GCM on a huge multipart", ForceAESGCMContentType, 1 << 30, true, "aes-gcm"},
		{"forced CTR on a tiny body", ForceAESCTRContentType, 1024, false, "aes-ctr"},
		{"empty body", "application/octet-stream", 0, false, "aes-gcm"},
		{"unknown length", "application/octet-stream", -1, false, "aes-gcm"},
		{"exactly at threshold", "text/plain", threshold, false, "aes-ctr"},
		{"one byte below threshold", "text/plain", threshold - 1, false, "aes-gcm"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contentType := DetermineContentTypeFromHTTPContentType(
				tc.httpContentType, tc.contentLength, tc.isMultipart, threshold)

			envelopeEncryptor, err := f.CreateEnvelopeEncryptor(contentType, keyEncryptor.Fingerprint(), "s3ep-")
			require.NoError(t, err, "content type %q returned by the decision function must be constructible", contentType)

			_, _, metadata, err := envelopeEncryptor.EncryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader([]byte("data"))), nil)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAlgorithm, metadata["s3ep-dek-algorithm"])
		})
	}
}

func TestFacKeyEncryptionTypeConstants(t *testing.T) {
	// The config layer matches on these literal strings; changing one silently
	// turns a configured provider into "unsupported key encryption type".
	assert.Equal(t, KeyEncryptionType("aes"), KeyEncryptionTypeAES)
	assert.Equal(t, KeyEncryptionType("tink"), KeyEncryptionTypeTink)
	assert.Equal(t, KeyEncryptionType("none"), KeyEncryptionTypeNone)
	assert.Equal(t, ContentType("multipart"), ContentTypeMultipart)
	assert.Equal(t, ContentType("whole"), ContentTypeWhole)

	// Provider names reported through GetRegisteredProviderInfo must match the
	// configuration type strings the factory accepts.
	var aesProvider encryption.KeyEncryptor = &keyencryption.AESProvider{}
	var noneProvider encryption.KeyEncryptor = &keyencryption.NoneProvider{}
	assert.Equal(t, string(KeyEncryptionTypeAES), aesProvider.Name())
	assert.Equal(t, string(KeyEncryptionTypeNone), noneProvider.Name())
}
