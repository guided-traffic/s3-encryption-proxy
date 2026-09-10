package factory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		// The exit provider is created like any other so that it can be the
		// active provider, but it holds no key material and refuses both key
		// operations instead of protecting a DEK.
		wantNoKeyMaterial bool
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
			name:              "exit ignores its config",
			keyType:           KeyEncryptionTypeExit,
			config:            map[string]interface{}{"anything": "ignored"},
			wantName:          "exit",
			wantNoKeyMaterial: true,
		},
		{
			name:              "exit accepts a nil config",
			keyType:           KeyEncryptionTypeExit,
			config:            nil,
			wantName:          "exit",
			wantNoKeyMaterial: true,
		},
		{
			name:    "none is no longer a key encryption type",
			keyType: KeyEncryptionType("none"),
			config:  nil,
			wantErr: "unsupported key encryption type: none",
		},
		{
			name:    "tink is no longer a key encryption type",
			keyType: KeyEncryptionType("tink"),
			config:  map[string]interface{}{"key_uri": "gcp-kms://whatever"},
			wantErr: "unsupported key encryption type: tink",
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

			dek := bytes.Repeat([]byte{0x11}, 32)

			if tt.wantNoKeyMaterial {
				_, err := keyEncryptor.EncryptDEK(context.Background(), dek)
				require.ErrorIs(t, err, keyencryption.ErrExitProviderKeyUse)
				_, err = keyEncryptor.DecryptDEK(context.Background(), dek)
				require.ErrorIs(t, err, keyencryption.ErrExitProviderKeyUse)
				return
			}

			// A freshly created encryptor must be able to protect and recover a DEK.
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
	assert.Len(t, f.keyEncryptors, 1)
	got, err := f.GetKeyEncryptor(first.Fingerprint())
	require.NoError(t, err)
	assert.Same(t, second, got)

	// Registering a genuinely different key adds a second entry.
	other, err := f.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
		"aes_key": FacOtherAESKeyB64,
	})
	require.NoError(t, err)
	f.RegisterKeyEncryptor(other)
	assert.Len(t, f.keyEncryptors, 2)
	gotOther, err := f.GetKeyEncryptor(other.Fingerprint())
	require.NoError(t, err)
	assert.Same(t, other, gotOther)
}

func TestFacKeyEncryptionTypeConstants(t *testing.T) {
	// The config layer matches on these literal strings; changing one silently
	// turns a configured provider into "unsupported key encryption type".
	assert.Equal(t, KeyEncryptionType("aes"), KeyEncryptionTypeAES)
	assert.Equal(t, KeyEncryptionType("exit"), KeyEncryptionTypeExit)

	// Provider names must match the configuration type strings the factory accepts.
	var aesProvider encryption.KeyEncryptor = &keyencryption.AESProvider{}
	var exitProvider encryption.KeyEncryptor = &keyencryption.ExitProvider{}
	assert.Equal(t, string(KeyEncryptionTypeAES), aesProvider.Name())
	assert.Equal(t, string(KeyEncryptionTypeExit), exitProvider.Name())
}
