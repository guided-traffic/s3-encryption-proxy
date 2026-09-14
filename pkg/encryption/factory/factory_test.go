package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactory_CreateKeyEncryptorFromConfig(t *testing.T) {
	factory := NewFactory()

	t.Run("AES key encryptor", func(t *testing.T) {
		keyEncryptor, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES, map[string]interface{}{
			"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
		})
		assert.NoError(t, err)
		assert.NotNil(t, keyEncryptor)
		assert.NotEmpty(t, keyEncryptor.Fingerprint())
	})

	t.Run("rsa is no longer a key encryption type", func(t *testing.T) {
		_, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionType("rsa"), map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key encryption type")
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := factory.CreateKeyEncryptorFromConfig(KeyEncryptionType("unsupported"), map[string]interface{}{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key encryption type")
	})
}
