package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandEnvVars_NoVars(t *testing.T) {
	result, err := expandEnvVars("plain-value")
	require.NoError(t, err)
	assert.Equal(t, "plain-value", result)
}

func TestExpandEnvVars_EmptyString(t *testing.T) {
	result, err := expandEnvVars("")
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestExpandEnvVars_SingleVar(t *testing.T) {
	t.Setenv("TEST_EXPAND_KEY", "my-secret-value")

	result, err := expandEnvVars("${TEST_EXPAND_KEY}")
	require.NoError(t, err)
	assert.Equal(t, "my-secret-value", result)
}

func TestExpandEnvVars_VarWithSurroundingText(t *testing.T) {
	t.Setenv("TEST_EXPAND_HOST", "db.example.com")

	result, err := expandEnvVars("https://${TEST_EXPAND_HOST}:5432/mydb")
	require.NoError(t, err)
	assert.Equal(t, "https://db.example.com:5432/mydb", result)
}

func TestExpandEnvVars_MultipleVars(t *testing.T) {
	t.Setenv("TEST_EXPAND_USER", "admin")
	t.Setenv("TEST_EXPAND_PASS", "secret123")

	result, err := expandEnvVars("${TEST_EXPAND_USER}:${TEST_EXPAND_PASS}")
	require.NoError(t, err)
	assert.Equal(t, "admin:secret123", result)
}

func TestExpandEnvVars_UnsetVarReturnsError(t *testing.T) {
	os.Unsetenv("TEST_EXPAND_MISSING")

	_, err := expandEnvVars("${TEST_EXPAND_MISSING}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment variable ${TEST_EXPAND_MISSING} is not set or empty")
}

func TestExpandEnvVars_EmptyVarReturnsError(t *testing.T) {
	t.Setenv("TEST_EXPAND_EMPTY", "")

	_, err := expandEnvVars("${TEST_EXPAND_EMPTY}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment variable ${TEST_EXPAND_EMPTY} is not set or empty")
}

func TestExpandEnvVars_BareDoublareNotExpanded(t *testing.T) {
	// $VAR without braces should NOT be expanded
	result, err := expandEnvVars("$NOT_EXPANDED")
	require.NoError(t, err)
	assert.Equal(t, "$NOT_EXPANDED", result)
}

func TestExpandEnvVars_MultilineValue(t *testing.T) {
	pemKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
	t.Setenv("TEST_EXPAND_PEM", pemKey)

	result, err := expandEnvVars("${TEST_EXPAND_PEM}")
	require.NoError(t, err)
	assert.Equal(t, pemKey, result)
}

func TestExpandConfigEnvVars_S3Backend(t *testing.T) {
	t.Setenv("TEST_S3_ACCESS_KEY", "my-access-key")
	t.Setenv("TEST_S3_SECRET_KEY", "my-secret-key")

	cfg := &Config{
		S3Backend: S3BackendConfig{
			AccessKeyID: "${TEST_S3_ACCESS_KEY}",
			SecretKey:   "${TEST_S3_SECRET_KEY}",
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, "my-access-key", cfg.S3Backend.AccessKeyID)
	assert.Equal(t, "my-secret-key", cfg.S3Backend.SecretKey)
}

func TestExpandConfigEnvVars_S3Clients(t *testing.T) {
	t.Setenv("TEST_CLIENT_KEY", "client-key-id")
	t.Setenv("TEST_CLIENT_SECRET", "client-secret-value")

	cfg := &Config{
		S3Clients: []S3ClientCredentials{
			{
				AccessKeyID: "${TEST_CLIENT_KEY}",
				SecretKey:   "${TEST_CLIENT_SECRET}",
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, "client-key-id", cfg.S3Clients[0].AccessKeyID)
	assert.Equal(t, "client-secret-value", cfg.S3Clients[0].SecretKey)
}

func TestExpandConfigEnvVars_ProviderConfig(t *testing.T) {
	t.Setenv("TEST_AES_KEY", "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=")

	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "${TEST_AES_KEY}",
					},
				},
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=", cfg.Encryption.Providers[0].Config["aes_key"])
}

func TestExpandConfigEnvVars_RSAProviderConfig(t *testing.T) {
	pubKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
	privKey := "-----BEGIN PRIVATE KEY-----\nMIIEvAIBA...\n-----END PRIVATE KEY-----"

	t.Setenv("TEST_RSA_PUB", pubKey)
	t.Setenv("TEST_RSA_PRIV", privKey)

	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "rsa",
					Type:  "rsa",
					Config: map[string]interface{}{
						"public_key_pem":  "${TEST_RSA_PUB}",
						"private_key_pem": "${TEST_RSA_PRIV}",
					},
				},
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, pubKey, cfg.Encryption.Providers[0].Config["public_key_pem"])
	assert.Equal(t, privKey, cfg.Encryption.Providers[0].Config["private_key_pem"])
}

func TestExpandConfigEnvVars_MissingVarReturnsError(t *testing.T) {
	os.Unsetenv("TEST_MISSING_VAR")

	cfg := &Config{
		S3Backend: S3BackendConfig{
			SecretKey: "${TEST_MISSING_VAR}",
		},
	}

	err := expandConfigEnvVars(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s3_backend.secret_key")
	assert.Contains(t, err.Error(), "TEST_MISSING_VAR")
}

func TestExpandConfigEnvVars_MissingProviderVarReturnsError(t *testing.T) {
	os.Unsetenv("TEST_MISSING_AES_KEY")

	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "${TEST_MISSING_AES_KEY}",
					},
				},
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption.providers[0].config.aes_key")
	assert.Contains(t, err.Error(), "TEST_MISSING_AES_KEY")
}

func TestExpandConfigEnvVars_PlainValuesUnchanged(t *testing.T) {
	cfg := &Config{
		S3Backend: S3BackendConfig{
			AccessKeyID: "plainuser",
			SecretKey:   "plainpassword",
		},
		S3Clients: []S3ClientCredentials{
			{
				AccessKeyID: "client1",
				SecretKey:   "clientsecret1",
			},
		},
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=",
					},
				},
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, "plainuser", cfg.S3Backend.AccessKeyID)
	assert.Equal(t, "plainpassword", cfg.S3Backend.SecretKey)
	assert.Equal(t, "client1", cfg.S3Clients[0].AccessKeyID)
	assert.Equal(t, "clientsecret1", cfg.S3Clients[0].SecretKey)
	assert.Equal(t, "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4=", cfg.Encryption.Providers[0].Config["aes_key"])
}

func TestExpandConfigEnvVars_NonStringProviderConfigSkipped(t *testing.T) {
	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{
				{
					Alias: "test",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key":     "some-key",
						"numeric_val": 42,
						"bool_val":    true,
					},
				},
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, 42, cfg.Encryption.Providers[0].Config["numeric_val"])
	assert.Equal(t, true, cfg.Encryption.Providers[0].Config["bool_val"])
}

func TestExpandConfigEnvVars_MultipleClientsWithMixedRefs(t *testing.T) {
	t.Setenv("TEST_CLIENT2_SECRET", "env-secret-value")

	cfg := &Config{
		S3Clients: []S3ClientCredentials{
			{
				AccessKeyID: "plain-key",
				SecretKey:   "plain-secret-minimum",
			},
			{
				AccessKeyID: "another-key",
				SecretKey:   "${TEST_CLIENT2_SECRET}",
			},
		},
	}

	err := expandConfigEnvVars(cfg)
	require.NoError(t, err)
	assert.Equal(t, "plain-secret-minimum", cfg.S3Clients[0].SecretKey)
	assert.Equal(t, "env-secret-value", cfg.S3Clients[1].SecretKey)
}
