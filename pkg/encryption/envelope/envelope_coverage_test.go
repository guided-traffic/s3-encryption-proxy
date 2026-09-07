package envelope

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// ---------------------------------------------------------------------------
// Test doubles and helpers (all prefixed with "Env" to stay collision free)
// ---------------------------------------------------------------------------

// EnvKEKMask is the XOR mask used by EnvFakeKeyEncryptor to simulate a
// reversible key wrapping without pulling in real crypto.
const EnvKEKMask byte = 0xA5

// EnvMask returns a new slice with every byte of in XORed with EnvKEKMask.
func EnvMask(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ EnvKEKMask
	}
	return out
}

// EnvSHA256 returns the hex encoded SHA-256 digest of everything r yields.
func EnvSHA256(t *testing.T, r io.Reader) string {
	t.Helper()
	hasher := sha256.New()
	_, err := io.Copy(hasher, r)
	require.NoError(t, err)
	return hex.EncodeToString(hasher.Sum(nil))
}

// EnvDigest returns the hex encoded SHA-256 digest of a byte slice.
func EnvDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EnvRandomBytes returns n cryptographically random bytes.
func EnvRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}

// EnvNewAESKEK builds a real AES KeyEncryptor from a deterministic 32 byte key
// derived from seed, so different seeds yield different KEKs.
func EnvNewAESKEK(t *testing.T, seed string) encryption.KeyEncryptor {
	t.Helper()
	key := sha256.Sum256([]byte(seed))
	kek, err := keyencryption.NewAESKeyEncryptor(key[:])
	require.NoError(t, err)
	return kek
}

// EnvFakeKeyEncryptor is a deterministic KeyEncryptor used to drive the
// envelope error paths and to observe what the envelope hands to the KEK layer.
type EnvFakeKeyEncryptor struct {
	name        string
	fingerprint string

	encryptErr error
	decryptErr error
	rotateErr  error

	// aliasDEK makes EncryptDEK return the caller's slice itself instead of a
	// copy, reproducing the pass-through ("none") KEK provider behaviour.
	aliasDEK bool

	observedPlainDEK []byte // copy of the DEK handed to EncryptDEK
	returnedDEK      []byte // the exact slice returned by DecryptDEK
	lastDecryptKeyID string
	decryptCalls     int
	rotateCalls      int
}

// EncryptDEK wraps the DEK by XOR masking it.
func (f *EnvFakeKeyEncryptor) EncryptDEK(_ context.Context, dek []byte) ([]byte, string, error) {
	if f.encryptErr != nil {
		return nil, "", f.encryptErr
	}
	f.observedPlainDEK = append([]byte(nil), dek...)
	if f.aliasDEK {
		return dek, f.fingerprint, nil
	}
	return EnvMask(dek), f.fingerprint, nil
}

// DecryptDEK unwraps the DEK by XOR masking it back.
func (f *EnvFakeKeyEncryptor) DecryptDEK(_ context.Context, encryptedDEK []byte, keyID string) ([]byte, error) {
	f.decryptCalls++
	f.lastDecryptKeyID = keyID
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	f.returnedDEK = EnvMask(encryptedDEK)
	return f.returnedDEK, nil
}

// Name returns the configured provider name.
func (f *EnvFakeKeyEncryptor) Name() string { return f.name }

// Fingerprint returns the configured fingerprint.
func (f *EnvFakeKeyEncryptor) Fingerprint() string { return f.fingerprint }

// RotateKEK records the call and returns the configured error.
func (f *EnvFakeKeyEncryptor) RotateKEK(_ context.Context) error {
	f.rotateCalls++
	return f.rotateErr
}

// EnvFakeDataEncryptor is a DataEncryptor test double that does not implement
// IVProvider, so the envelope must omit the aes-iv metadata entry.
type EnvFakeDataEncryptor struct {
	algorithm string

	generatedDEK []byte // exact slice returned by GenerateDEK
	genErr       error
	encErr       error
	decErr       error

	observedEncryptDEK []byte
	observedDecryptDEK []byte
	observedIV         []byte
	observedAAD        []byte
	payload            []byte // bytes the returned readers yield
}

// EncryptStream records its inputs and returns the configured payload.
func (f *EnvFakeDataEncryptor) EncryptStream(_ context.Context, reader *bufio.Reader, dek []byte, associatedData []byte) (*bufio.Reader, error) {
	if f.encErr != nil {
		return nil, f.encErr
	}
	f.observedEncryptDEK = append([]byte(nil), dek...)
	f.observedAAD = append([]byte(nil), associatedData...)
	if reader != nil {
		consumed, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		f.payload = consumed
	}
	return bufio.NewReader(bytes.NewReader(f.payload)), nil
}

// DecryptStream records its inputs and returns the configured payload.
func (f *EnvFakeDataEncryptor) DecryptStream(_ context.Context, encryptedReader *bufio.Reader, dek []byte, iv []byte, associatedData []byte) (*bufio.Reader, error) {
	if f.decErr != nil {
		return nil, f.decErr
	}
	f.observedDecryptDEK = append([]byte(nil), dek...)
	f.observedIV = append([]byte(nil), iv...)
	f.observedAAD = append([]byte(nil), associatedData...)
	if encryptedReader != nil {
		consumed, err := io.ReadAll(encryptedReader)
		if err != nil {
			return nil, err
		}
		f.payload = consumed
	}
	return bufio.NewReader(bytes.NewReader(f.payload)), nil
}

// GenerateDEK returns the retained DEK slice so tests can observe zeroization.
func (f *EnvFakeDataEncryptor) GenerateDEK(_ context.Context) ([]byte, error) {
	if f.genErr != nil {
		return nil, f.genErr
	}
	if f.generatedDEK == nil {
		f.generatedDEK = bytes.Repeat([]byte{0x11}, 32)
	}
	return f.generatedDEK, nil
}

// Algorithm returns the configured algorithm identifier.
func (f *EnvFakeDataEncryptor) Algorithm() string { return f.algorithm }

// EnvFakeIVDataEncryptor additionally implements encryption.IVProvider.
type EnvFakeIVDataEncryptor struct {
	EnvFakeDataEncryptor
	iv []byte
}

// GetLastIV implements encryption.IVProvider.
func (f *EnvFakeIVDataEncryptor) GetLastIV() []byte { return f.iv }

// ---------------------------------------------------------------------------
// Construction and accessors
// ---------------------------------------------------------------------------

func TestEnvNewWiresProvidersAndAccessors(t *testing.T) {
	kek := &EnvFakeKeyEncryptor{name: "fake-kek", fingerprint: "fp-123"}
	dek := &EnvFakeDataEncryptor{algorithm: "fake-dek"}

	enc := New(kek, dek, "s3ep-")
	require.NotNil(t, enc)

	impl, ok := enc.(*EnvelopeEncryptor)
	require.True(t, ok, "New must return *EnvelopeEncryptor")

	assert.Same(t, kek, impl.GetKeyEncryptor(), "key encryptor must be handed back unchanged")
	assert.Same(t, dek, impl.GetDataEncryptor(), "data encryptor must be handed back unchanged")
	assert.Equal(t, "fp-123", enc.Fingerprint(), "envelope fingerprint is the KEK fingerprint")
	assert.Equal(t, "s3ep-", impl.metadataPrefix)
}

func TestEnvFingerprintTracksKeyEncryptor(t *testing.T) {
	kekA := EnvNewAESKEK(t, "fingerprint-a")
	kekB := EnvNewAESKEK(t, "fingerprint-b")

	encA := New(kekA, dataencryption.NewAESGCMDataEncryptor(), "s3ep-")
	encB := New(kekB, dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

	assert.Equal(t, kekA.Fingerprint(), encA.Fingerprint())
	assert.NotEqual(t, encA.Fingerprint(), encB.Fingerprint(), "different KEKs must yield different fingerprints")
	assert.Len(t, encA.Fingerprint(), 64, "AES KEK fingerprint is a hex SHA-256")
}

func TestEnvRotateKEKDelegatesToKeyEncryptor(t *testing.T) {
	rotateErr := errors.New("rotation refused")

	t.Run("error is propagated verbatim", func(t *testing.T) {
		kek := &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp", rotateErr: rotateErr}
		enc := New(kek, &EnvFakeDataEncryptor{algorithm: "fake"}, "s3ep-")

		err := enc.RotateKEK(context.Background())
		require.Error(t, err)
		assert.Same(t, rotateErr, err, "RotateKEK must not wrap the provider error")
		assert.Equal(t, 1, kek.rotateCalls)
	})

	t.Run("success is propagated", func(t *testing.T) {
		kek := &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"}
		enc := New(kek, &EnvFakeDataEncryptor{algorithm: "fake"}, "s3ep-")

		require.NoError(t, enc.RotateKEK(context.Background()))
		assert.Equal(t, 1, kek.rotateCalls)
	})

	t.Run("real AES KEK reports unimplemented rotation", func(t *testing.T) {
		enc := New(EnvNewAESKEK(t, "rotate"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")
		err := enc.RotateKEK(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})
}

// ---------------------------------------------------------------------------
// Round trips with the real providers
// ---------------------------------------------------------------------------

func TestEnvEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		newDataEnc    func() encryption.DataEncryptor
		algorithm     string
		plaintext     []byte
		passIVOnRead  bool // GCM prepends its nonce, so the IV must stay nil there
		expectIVLen   int
		associatedAAD []byte
	}{
		{
			name:          "gcm small payload",
			newDataEnc:    dataencryption.NewAESGCMDataEncryptor,
			algorithm:     "aes-gcm",
			plaintext:     []byte("Hello, envelope encryption!"),
			expectIVLen:   12, // GCM nonce
			associatedAAD: []byte("bucket/object-key"),
		},
		{
			name:          "gcm empty payload",
			newDataEnc:    dataencryption.NewAESGCMDataEncryptor,
			algorithm:     "aes-gcm",
			plaintext:     []byte{},
			expectIVLen:   12, // GCM nonce
			associatedAAD: []byte("bucket/empty"),
		},
		{
			name:          "ctr small payload",
			newDataEnc:    dataencryption.NewAESCTRDataEncryptor,
			algorithm:     "aes-ctr",
			plaintext:     []byte("Hello, streaming envelope!"),
			passIVOnRead:  true,
			expectIVLen:   16, // CTR IV
			associatedAAD: []byte("bucket/object-key"),
		},
		{
			name:          "ctr multi buffer payload",
			newDataEnc:    dataencryption.NewAESCTRDataEncryptor,
			algorithm:     "aes-ctr",
			plaintext:     EnvRandomBytes(t, 256*1024),
			passIVOnRead:  true,
			expectIVLen:   16, // CTR IV
			associatedAAD: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := EnvNewAESKEK(t, "round-trip")
			enc := New(kek, tt.newDataEnc(), "s3ep-")

			plainDigest := EnvDigest(tt.plaintext)

			encryptedReader, encryptedDEK, metadata, err := enc.EncryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader(tt.plaintext)), tt.associatedAAD)
			require.NoError(t, err)
			require.NotNil(t, encryptedReader)
			require.NotEmpty(t, encryptedDEK)

			ciphertext, err := io.ReadAll(encryptedReader)
			require.NoError(t, err)
			assert.NotEqual(t, plainDigest, EnvDigest(ciphertext), "ciphertext must differ from plaintext")
			if len(tt.plaintext) > 0 {
				assert.False(t, bytes.Contains(ciphertext, tt.plaintext), "plaintext must not appear in the ciphertext")
			}

			// Metadata contract: prefixed keys only, nothing beyond the allow list.
			assert.Equal(t, tt.algorithm, metadata["s3ep-dek-algorithm"])
			assert.Equal(t, "aes", metadata["s3ep-kek-algorithm"])
			assert.Equal(t, kek.Fingerprint(), metadata["s3ep-kek-fingerprint"])
			assert.NotContains(t, metadata, "s3ep-provider-alias", "provider alias must never reach metadata")

			mdDEK, err := base64.StdEncoding.DecodeString(metadata["s3ep-encrypted-dek"])
			require.NoError(t, err)
			assert.Equal(t, encryptedDEK, mdDEK, "returned encrypted DEK must match the metadata copy")

			var iv []byte
			require.Contains(t, metadata, "s3ep-aes-iv")
			iv, err = base64.StdEncoding.DecodeString(metadata["s3ep-aes-iv"])
			require.NoError(t, err)
			assert.Len(t, iv, tt.expectIVLen)
			if !tt.passIVOnRead {
				iv = nil
			}

			decryptedReader, err := enc.DecryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, iv, tt.associatedAAD)
			require.NoError(t, err)
			assert.Equal(t, plainDigest, EnvSHA256(t, decryptedReader), "round trip must reproduce the plaintext")
		})
	}
}

func TestEnvEncryptedDEKMatchesMetadataForPassThroughKEK(t *testing.T) {
	// Regression guard: the "none" KEK provider returns the DEK slice itself,
	// which the deferred DEK zeroization used to wipe before the caller saw it.
	kek, err := keyencryption.NewNoneProvider(nil)
	require.NoError(t, err)

	enc := New(kek, dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

	_, encryptedDEK, metadata, err := enc.EncryptDataStream(
		context.Background(), bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)
	require.NoError(t, err)

	mdDEK, err := base64.StdEncoding.DecodeString(metadata["s3ep-encrypted-dek"])
	require.NoError(t, err)

	assert.Equal(t, mdDEK, encryptedDEK, "returned encrypted DEK must match the metadata copy")
	assert.NotEqual(t, make([]byte, len(encryptedDEK)), encryptedDEK, "returned encrypted DEK must not be zeroed")

	// Same guarantee against an aliasing key encryptor in isolation.
	aliasing := &EnvFakeKeyEncryptor{name: "aliasing", fingerprint: "fp", aliasDEK: true}
	retained := bytes.Repeat([]byte{0x3F}, 32)
	fakeEnc := New(aliasing, &EnvFakeDataEncryptor{algorithm: "fake", generatedDEK: retained}, "s3ep-")

	_, aliasedDEK, aliasedMD, err := fakeEnc.EncryptDataStream(
		context.Background(), bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)
	require.NoError(t, err)

	assert.Equal(t, bytes.Repeat([]byte{0x3F}, 32), aliasedDEK, "the wrapped DEK must survive the plaintext DEK wipe")
	assert.Equal(t, base64.StdEncoding.EncodeToString(aliasedDEK), aliasedMD["s3ep-encrypted-dek"])
	assert.Equal(t, make([]byte, 32), retained, "the plaintext DEK buffer must still be wiped")
}

func TestEnvMetadataPrefixIsApplied(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "default prefix", prefix: "s3ep-"},
		{name: "custom prefix", prefix: "custom-x_"},
		{name: "empty prefix", prefix: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := EnvNewAESKEK(t, "prefix")
			enc := New(kek, dataencryption.NewAESCTRDataEncryptor(), tt.prefix)

			_, _, metadata, err := enc.EncryptDataStream(
				context.Background(), bufio.NewReader(bytes.NewReader([]byte("data"))), nil)
			require.NoError(t, err)

			expectedKeys := []string{
				tt.prefix + "dek-algorithm",
				tt.prefix + "encrypted-dek",
				tt.prefix + "kek-algorithm",
				tt.prefix + "kek-fingerprint",
				tt.prefix + "aes-iv",
			}
			assert.Len(t, metadata, len(expectedKeys), "no metadata entries beyond the allow list")
			for _, key := range expectedKeys {
				assert.Contains(t, metadata, key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tampering and wrong-key behaviour
// ---------------------------------------------------------------------------

func TestEnvGCMTamperingIsDetected(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("integrity protected payload")
	aad := []byte("bucket/object")

	encryptOnce := func(t *testing.T) (encryption.EnvelopeEncryptor, []byte, []byte) {
		t.Helper()
		enc := New(EnvNewAESKEK(t, "tamper"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")
		reader, encryptedDEK, _, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader(plaintext)), aad)
		require.NoError(t, err)
		ciphertext, err := io.ReadAll(reader)
		require.NoError(t, err)
		return enc, ciphertext, encryptedDEK
	}

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		enc, ciphertext, encryptedDEK := encryptOnce(t)
		ciphertext[len(ciphertext)-1] ^= 0xFF

		_, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, aad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})

	t.Run("flipped nonce byte", func(t *testing.T) {
		enc, ciphertext, encryptedDEK := encryptOnce(t)
		ciphertext[0] ^= 0x01

		_, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, aad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})

	t.Run("tampered encrypted DEK", func(t *testing.T) {
		enc, ciphertext, encryptedDEK := encryptOnce(t)
		tampered := append([]byte(nil), encryptedDEK...)
		tampered[len(tampered)-1] ^= 0x01

		_, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), tampered, nil, aad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})

	t.Run("mismatched associated data", func(t *testing.T) {
		enc, ciphertext, encryptedDEK := encryptOnce(t)

		_, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, []byte("bucket/other-object"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		enc, ciphertext, encryptedDEK := encryptOnce(t)

		_, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext[:8])), encryptedDEK, nil, aad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})
}

func TestEnvGCMMetadataIVMustNotBeReplayed(t *testing.T) {
	// The envelope stores the GCM nonce in "aes-iv" metadata even though the
	// GCM data encryptor also prepends that nonce to the ciphertext. Feeding
	// the metadata IV back into DecryptDataStream therefore makes the nonce
	// bytes part of the ciphertext and authentication fails. Callers must pass
	// a nil IV for GCM; this test pins that trap so it cannot regress silently.
	ctx := context.Background()
	enc := New(EnvNewAESKEK(t, "gcm-iv"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

	reader, encryptedDEK, metadata, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(reader)
	require.NoError(t, err)

	iv, err := base64.StdEncoding.DecodeString(metadata["s3ep-aes-iv"])
	require.NoError(t, err)
	require.Len(t, iv, 12)
	assert.Equal(t, iv, ciphertext[:12], "the GCM nonce is stored twice: in metadata and in front of the ciphertext")

	_, err = enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, iv, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message authentication failed")

	// The supported call shape (nil IV) round trips.
	decrypted, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, EnvDigest([]byte("payload")), EnvSHA256(t, decrypted))
}

func TestEnvDecryptWithWrongKEK(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("payload encrypted under KEK A")

	t.Run("gcm rejects a foreign KEK", func(t *testing.T) {
		encA := New(EnvNewAESKEK(t, "kek-a"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")
		encB := New(EnvNewAESKEK(t, "kek-b"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

		reader, encryptedDEK, _, err := encA.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader(plaintext)), nil)
		require.NoError(t, err)
		ciphertext, err := io.ReadAll(reader)
		require.NoError(t, err)

		_, err = encB.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, nil)
		require.Error(t, err, "a wrong KEK must not yield plaintext")
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
	})

	t.Run("ctr yields garbage instead of plaintext", func(t *testing.T) {
		// AES-CTR is unauthenticated by design; the HMAC layer above the
		// envelope catches this. The envelope must at least never emit the
		// original plaintext under a foreign KEK.
		encA := New(EnvNewAESKEK(t, "kek-a"), dataencryption.NewAESCTRDataEncryptor(), "s3ep-")
		encB := New(EnvNewAESKEK(t, "kek-b"), dataencryption.NewAESCTRDataEncryptor(), "s3ep-")

		reader, encryptedDEK, metadata, err := encA.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader(plaintext)), nil)
		require.NoError(t, err)
		ciphertext, err := io.ReadAll(reader)
		require.NoError(t, err)
		iv, err := base64.StdEncoding.DecodeString(metadata["s3ep-aes-iv"])
		require.NoError(t, err)

		decrypted, err := encB.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, iv, nil)
		require.NoError(t, err)
		assert.NotEqual(t, EnvDigest(plaintext), EnvSHA256(t, decrypted), "wrong KEK must not reproduce the plaintext")
	})
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestEnvEncryptDataStreamErrorPaths(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("provider failure")

	tests := []struct {
		name       string
		keyEnc     *EnvFakeKeyEncryptor
		dataEnc    *EnvFakeDataEncryptor
		wantPrefix string
	}{
		{
			name:       "DEK generation fails",
			keyEnc:     &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"},
			dataEnc:    &EnvFakeDataEncryptor{algorithm: "fake", genErr: sentinel},
			wantPrefix: "failed to generate DEK",
		},
		{
			name:       "data encryption fails",
			keyEnc:     &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"},
			dataEnc:    &EnvFakeDataEncryptor{algorithm: "fake", encErr: sentinel},
			wantPrefix: "failed to encrypt data with DEK",
		},
		{
			name:       "DEK wrapping fails",
			keyEnc:     &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp", encryptErr: sentinel},
			dataEnc:    &EnvFakeDataEncryptor{algorithm: "fake"},
			wantPrefix: "failed to encrypt DEK with KEK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := New(tt.keyEnc, tt.dataEnc, "s3ep-")

			reader, encryptedDEK, metadata, err := enc.EncryptDataStream(
				ctx, bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantPrefix)
			assert.ErrorIs(t, err, sentinel, "the provider error must stay unwrappable")
			assert.Nil(t, reader, "no reader may escape on failure")
			assert.Nil(t, encryptedDEK)
			assert.Nil(t, metadata, "no metadata may escape on failure")
		})
	}
}

func TestEnvDecryptDataStreamErrorPaths(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("provider failure")

	t.Run("DEK unwrapping fails", func(t *testing.T) {
		enc := New(
			&EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp", decryptErr: sentinel},
			&EnvFakeDataEncryptor{algorithm: "fake"},
			"s3ep-",
		)

		reader, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("ct"))), []byte("wrapped"), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK")
		assert.ErrorIs(t, err, sentinel)
		assert.Nil(t, reader)
	})

	t.Run("data decryption fails", func(t *testing.T) {
		enc := New(
			&EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"},
			&EnvFakeDataEncryptor{algorithm: "fake", decErr: sentinel},
			"s3ep-",
		)

		reader, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("ct"))), []byte("wrapped"), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
		assert.ErrorIs(t, err, sentinel)
		assert.Nil(t, reader)
	})

	t.Run("encrypted DEK shorter than the AES block size", func(t *testing.T) {
		enc := New(EnvNewAESKEK(t, "short-dek"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

		reader, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("ct"))), []byte{0x01, 0x02}, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK")
		assert.Contains(t, err.Error(), "too short")
		assert.Nil(t, reader)
	})

	t.Run("empty encrypted DEK", func(t *testing.T) {
		enc := New(EnvNewAESKEK(t, "empty-dek"), dataencryption.NewAESGCMDataEncryptor(), "s3ep-")

		reader, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("ct"))), nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK")
		assert.Nil(t, reader)
	})

	t.Run("CTR without an IV is rejected", func(t *testing.T) {
		enc := New(EnvNewAESKEK(t, "ctr-no-iv"), dataencryption.NewAESCTRDataEncryptor(), "s3ep-")

		reader, encryptedDEK, _, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("payload"))), nil)
		require.NoError(t, err)
		ciphertext, err := io.ReadAll(reader)
		require.NoError(t, err)

		decrypted, err := enc.DecryptDataStream(ctx, bufio.NewReader(bytes.NewReader(ciphertext)), encryptedDEK, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data with DEK")
		assert.Contains(t, err.Error(), "invalid IV size")
		assert.Nil(t, decrypted)
	})
}

// ---------------------------------------------------------------------------
// IV metadata handling
// ---------------------------------------------------------------------------

func TestEnvIVMetadataHandling(t *testing.T) {
	ctx := context.Background()

	t.Run("IVProvider with an IV adds the aes-iv entry", func(t *testing.T) {
		iv := bytes.Repeat([]byte{0x2B}, 16)
		dataEnc := &EnvFakeIVDataEncryptor{
			EnvFakeDataEncryptor: EnvFakeDataEncryptor{algorithm: "fake-ctr"},
			iv:                   iv,
		}
		enc := New(&EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"}, dataEnc, "s3ep-")

		_, _, metadata, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("x"))), nil)
		require.NoError(t, err)

		assert.Equal(t, base64.StdEncoding.EncodeToString(iv), metadata["s3ep-aes-iv"])
		assert.Len(t, metadata, 5)
	})

	t.Run("IVProvider returning nil omits the aes-iv entry", func(t *testing.T) {
		dataEnc := &EnvFakeIVDataEncryptor{
			EnvFakeDataEncryptor: EnvFakeDataEncryptor{algorithm: "fake-ctr"},
			iv:                   nil,
		}
		enc := New(&EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"}, dataEnc, "s3ep-")

		_, _, metadata, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("x"))), nil)
		require.NoError(t, err)

		assert.NotContains(t, metadata, "s3ep-aes-iv")
		assert.Len(t, metadata, 4)
	})

	t.Run("non IVProvider omits the aes-iv entry", func(t *testing.T) {
		dataEnc := &EnvFakeDataEncryptor{algorithm: "fake-plain"}
		enc := New(&EnvFakeKeyEncryptor{name: "fake-kek", fingerprint: "fp"}, dataEnc, "s3ep-")

		_, _, metadata, err := enc.EncryptDataStream(ctx, bufio.NewReader(bytes.NewReader([]byte("x"))), nil)
		require.NoError(t, err)

		assert.NotContains(t, metadata, "s3ep-aes-iv")
		assert.Equal(t, map[string]string{
			"s3ep-dek-algorithm":   "fake-plain",
			"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString(EnvMask(bytes.Repeat([]byte{0x11}, 32))),
			"s3ep-kek-algorithm":   "fake-kek",
			"s3ep-kek-fingerprint": "fp",
		}, metadata)
	})
}

// ---------------------------------------------------------------------------
// DEK handling: zeroization, forwarding and KEK key id
// ---------------------------------------------------------------------------

func TestEnvEncryptZeroesGeneratedDEK(t *testing.T) {
	retained := bytes.Repeat([]byte{0x7C}, 32)
	dataEnc := &EnvFakeDataEncryptor{algorithm: "fake", generatedDEK: retained}
	keyEnc := &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"}

	enc := New(keyEnc, dataEnc, "s3ep-")
	_, _, _, err := enc.EncryptDataStream(context.Background(), bufio.NewReader(bytes.NewReader([]byte("payload"))), []byte("aad"))
	require.NoError(t, err)

	assert.Equal(t, bytes.Repeat([]byte{0x7C}, 32), dataEnc.observedEncryptDEK, "the plaintext DEK must reach the data encryptor")
	assert.Equal(t, bytes.Repeat([]byte{0x7C}, 32), keyEnc.observedPlainDEK, "the plaintext DEK must reach the key encryptor")
	assert.Equal(t, make([]byte, 32), retained, "the generated DEK must be wiped once encryption returns")
	assert.Equal(t, []byte("aad"), dataEnc.observedAAD, "associated data must be forwarded untouched")
}

func TestEnvDecryptZeroesUnwrappedDEK(t *testing.T) {
	keyEnc := &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fp"}
	dataEnc := &EnvFakeDataEncryptor{algorithm: "fake"}
	enc := New(keyEnc, dataEnc, "s3ep-")

	wrapped := EnvMask(bytes.Repeat([]byte{0x5D}, 32))
	iv := bytes.Repeat([]byte{0x09}, 16)

	reader, err := enc.DecryptDataStream(
		context.Background(), bufio.NewReader(bytes.NewReader([]byte("ciphertext"))), wrapped, iv, []byte("aad"))
	require.NoError(t, err)
	require.NotNil(t, reader)

	assert.Equal(t, bytes.Repeat([]byte{0x5D}, 32), dataEnc.observedDecryptDEK, "the unwrapped DEK must reach the data encryptor")
	assert.Equal(t, iv, dataEnc.observedIV, "the IV must be forwarded untouched")
	assert.Equal(t, []byte("aad"), dataEnc.observedAAD, "associated data must be forwarded untouched")
	assert.Equal(t, make([]byte, 32), keyEnc.returnedDEK, "the unwrapped DEK must be wiped once decryption returns")
}

func TestEnvDecryptPassesOwnFingerprintAsKeyID(t *testing.T) {
	// Documented behaviour: the envelope never receives the key id stored in
	// object metadata, it always re-uses the fingerprint of its own KEK. The
	// provider is therefore selected before the envelope is built.
	keyEnc := &EnvFakeKeyEncryptor{name: "fake", fingerprint: "fingerprint-of-configured-kek"}
	enc := New(keyEnc, &EnvFakeDataEncryptor{algorithm: "fake"}, "s3ep-")

	_, err := enc.DecryptDataStream(
		context.Background(), bufio.NewReader(bytes.NewReader([]byte("ct"))), []byte("wrapped"), nil, nil)
	require.NoError(t, err)

	assert.Equal(t, 1, keyEnc.decryptCalls)
	assert.Equal(t, "fingerprint-of-configured-kek", keyEnc.lastDecryptKeyID)
}

func TestEnvStreamingIsLazyForCTR(t *testing.T) {
	// The CTR path must not buffer the payload: EncryptDataStream returns
	// before the source reader has been drained.
	source := &EnvCountingReader{data: EnvRandomBytes(t, 128*1024)}
	enc := New(EnvNewAESKEK(t, "lazy"), dataencryption.NewAESCTRDataEncryptor(), "s3ep-")

	encryptedReader, _, _, err := enc.EncryptDataStream(context.Background(), bufio.NewReader(source), nil)
	require.NoError(t, err)

	assert.Less(t, source.read, len(source.data), "CTR encryption must not read the whole payload up front")

	consumed, err := io.ReadAll(encryptedReader)
	require.NoError(t, err)
	assert.Len(t, consumed, len(source.data), "ciphertext length must match plaintext length for CTR")
}

// EnvCountingReader counts how many bytes have been pulled from it.
type EnvCountingReader struct {
	data []byte
	read int
}

// Read implements io.Reader.
func (r *EnvCountingReader) Read(p []byte) (int, error) {
	if r.read >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.read:])
	r.read += n
	return n, nil
}
