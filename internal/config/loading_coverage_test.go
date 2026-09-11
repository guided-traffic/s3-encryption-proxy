package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CfgResetViper clears the global viper state before and after a test so that
// the package level singleton cannot leak between test cases.
func CfgResetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

// CfgNoLicense neutralises every environment variable the license loader reads
// so that license dependent behaviour is deterministic.
func CfgNoLicense(t *testing.T) {
	t.Helper()
	t.Setenv("S3EP_LICENSE", "")
	t.Setenv("S3EP_LICENSE_TOKEN", "")
	t.Setenv("S3_ENCRYPTION_PROXY_LICENSE", "")
}

// CfgWriteConfigFile writes body to <dir>/<name> and returns the full path.
func CfgWriteConfigFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// CfgMinimalYAML is a complete, valid configuration that requires no license.
const CfgMinimalYAML = `
s3_backend:
  target_endpoint: "https://minio:9000"
  region: "eu-central-1"
  access_key_id: "backendkey"
  secret_key: "backendsecret"
encryption:
  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
      description: "leaving the product"
      config: {}
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
    description: "unit test client"
`

func TestCfgInitConfigWithExplicitFile(t *testing.T) {
	CfgResetViper(t)

	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", CfgMinimalYAML+"\nlog_level: \"warn\"\n")
	InitConfig(path)

	assert.Equal(t, path, viper.ConfigFileUsed())
	assert.Equal(t, "warn", viper.GetString("log_level"))
	assert.Equal(t, "https://minio:9000", viper.GetString("s3_backend.target_endpoint"))
	// Defaults still apply for keys the file does not mention.
	assert.Equal(t, "0.0.0.0:8080", viper.GetString("bind_address"))
	assert.Equal(t, "s3ep-", viper.GetString("encryption.metadata_key_prefix"))
}

func TestCfgInitConfigDiscoversFileInHomeDirectory(t *testing.T) {
	CfgResetViper(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	path := CfgWriteConfigFile(t, home, ".s3-encryption-proxy.yaml", CfgMinimalYAML+"\nlog_format: \"json\"\n")

	InitConfig("")

	assert.Equal(t, path, viper.ConfigFileUsed())
	assert.Equal(t, "json", viper.GetString("log_format"))
}

func TestCfgInitConfigWithMissingFileKeepsDefaults(t *testing.T) {
	CfgResetViper(t)

	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	InitConfig(missing)

	// Reading failed silently; every default must still be in place.
	assert.Equal(t, "0.0.0.0:8080", viper.GetString("bind_address"))
	assert.Equal(t, "info", viper.GetString("log_level"))
	assert.Equal(t, "", viper.GetString("s3_backend.target_endpoint"))
}

func TestCfgInitConfigEnablesEnvPrefix(t *testing.T) {
	CfgResetViper(t)
	t.Setenv("S3EP_LOG_LEVEL", "trace")

	InitConfig(filepath.Join(t.TempDir(), "absent.yaml"))

	assert.Equal(t, "trace", viper.GetString("log_level"))
}

func TestCfgSetDefaults(t *testing.T) {
	CfgResetViper(t)
	setDefaults()

	assert.Equal(t, "0.0.0.0:8080", viper.GetString("bind_address"))
	assert.Equal(t, "info", viper.GetString("log_level"))
	assert.Equal(t, "text", viper.GetString("log_format"))
	assert.False(t, viper.GetBool("log_health_requests"))

	assert.Equal(t, "us-east-1", viper.GetString("s3_backend.region"))
	assert.False(t, viper.GetBool("s3_backend.insecure_skip_verify"))

	assert.False(t, viper.GetBool("tls.enabled"))
	assert.False(t, viper.GetBool("monitoring.enabled"))
	assert.Equal(t, ":9090", viper.GetString("monitoring.bind_address"))
	assert.Equal(t, "/metrics", viper.GetString("monitoring.metrics_path"))
	assert.Equal(t, "config/license.jwt", viper.GetString("license_file"))

	assert.Equal(t, 12*1024*1024, viper.GetInt("optimizations.streaming_segment_size"))
	assert.True(t, viper.GetBool("optimizations.clean_http_transfer_chunked"))
	assert.Equal(t, 300, viper.GetInt("optimizations.multipart_session_cleanup_interval"))
	assert.Equal(t, 3600, viper.GetInt("optimizations.multipart_session_max_age"))
	assert.Equal(t, 4, viper.GetInt("optimizations.multipart_upload_concurrency"))

	assert.Equal(t, "s3ep-", viper.GetString("encryption.metadata_key_prefix"))

	assert.Equal(t, 900, viper.GetInt("s3_security.max_clock_skew_seconds"))
}

func TestCfgLoadFromYAMLFile(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)

	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", CfgMinimalYAML)
	InitConfig(path)

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "https://minio:9000", cfg.S3Backend.TargetEndpoint)
	assert.Equal(t, "eu-central-1", cfg.S3Backend.Region)
	assert.Equal(t, "backendkey", cfg.S3Backend.AccessKeyID)
	assert.Equal(t, "backendsecret", cfg.S3Backend.SecretKey)

	// A YAML sequence reaches loadProvidersFromInterfaceSlice as []interface{}.
	require.Len(t, cfg.Encryption.Providers, 1)
	assert.Equal(t, "way-out", cfg.Encryption.Providers[0].Alias)
	assert.Equal(t, "exit", cfg.Encryption.Providers[0].Type)
	assert.Equal(t, "leaving the product", cfg.Encryption.Providers[0].Description)
	assert.Empty(t, cfg.Encryption.Providers[0].Config)

	require.Len(t, cfg.S3Clients, 1)
	assert.Equal(t, "clientkey01", cfg.S3Clients[0].AccessKeyID)

	// Defaults survive the round trip.
	assert.Equal(t, int64(12*1024*1024), cfg.Optimizations.StreamingSegmentSize)
	assert.Equal(t, 4, cfg.Optimizations.MultipartUploadConcurrency)
}

func TestCfgLoadProviderConfigFromYAMLKeepsNestedValues(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)

	body := `
s3_backend:
  target_endpoint: "https://minio:9000"
encryption:
  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
    - alias: "aes-legacy"
      type: "aes"
      config:
        aes_key: "` + CfgTestAESKey + `"
        rotation_days: 90
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`
	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
	InitConfig(path)

	cfg, err := Load()
	require.NoError(t, err)
	require.Len(t, cfg.Encryption.Providers, 2)

	assert.Empty(t, cfg.Encryption.Providers[0].Config)
	assert.Equal(t, CfgTestAESKey, cfg.Encryption.Providers[1].Config["aes_key"])
	assert.Equal(t, 90, cfg.Encryption.Providers[1].Config["rotation_days"])
}

func TestCfgMetadataKeyPrefix(t *testing.T) {
	CfgNoLicense(t)

	tests := []struct {
		name      string
		extraYAML string
		expect    string
		expectErr string
	}{
		{name: "default is s3ep-", extraYAML: "", expect: "s3ep-"},
		{name: "custom prefix wins", extraYAML: "  metadata_key_prefix: \"acme-\"\n", expect: "acme-"},
		{name: "digits and hyphens are allowed", extraYAML: "  metadata_key_prefix: \"acme2-enc-\"\n", expect: "acme2-enc-"},
		// D-30. An empty prefix made the writer store "encrypted-dek"
		// unprefixed while the read path still looked for "s3ep-", so
		// every GET decided the object was unencrypted and served the
		// ciphertext behind a 200. It used to be accepted, and the README
		// documented it as a way to store the metadata unprefixed.
		{name: "an empty prefix is refused, it used to serve ciphertext as plaintext",
			extraYAML: "  metadata_key_prefix: \"\"\n", expectErr: "metadata_key_prefix"},
		// S3 lower-cases metadata keys in transit and the proxy's comparisons
		// do not, so a capital in the prefix silently disabled decryption and
		// leaked the encryption metadata to the client.
		{name: "an uppercase prefix is refused, it never matches on the way back",
			extraYAML: "  metadata_key_prefix: \"S3EP-\"\n", expectErr: "metadata_key_prefix"},
		{name: "an underscore is refused", extraYAML: "  metadata_key_prefix: \"s3ep_\"\n", expectErr: "metadata_key_prefix"},
		{name: "whitespace is refused", extraYAML: "  metadata_key_prefix: \"s3ep -\"\n", expectErr: "metadata_key_prefix"},
		// ADR 0009 D2. The trailing dash is what keeps the namespace separable:
		// without it a prefix also claims every client key that begins with it.
		// Four characters is the floor, so a two-letter prefix cannot collide
		// with a common metadata key by accident.
		{name: "a prefix with no trailing dash is refused",
			extraYAML: "  metadata_key_prefix: \"s3ep\"\n", expectErr: "ending in"},
		{name: "a prefix below four characters is refused",
			extraYAML: "  metadata_key_prefix: \"s3-\"\n", expectErr: "at least four characters"},
		{name: "a prefix starting with a dash is refused",
			extraYAML: "  metadata_key_prefix: \"-abc-\"\n", expectErr: "starting with a letter"},
		{name: "four characters ending in a dash is the shortest accepted",
			extraYAML: "  metadata_key_prefix: \"abc-\"\n", expect: "abc-"},
		{name: "a multi-segment prefix is accepted",
			extraYAML: "  metadata_key_prefix: \"x-s3ep-dev-\"\n", expect: "x-s3ep-dev-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CfgResetViper(t)

			body := `
s3_backend:
  target_endpoint: "https://minio:9000"
encryption:
  encryption_method_alias: "way-out"
` + tt.extraYAML + `  providers:
    - alias: "way-out"
      type: "exit"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`
			path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
			InitConfig(path)

			cfg, err := Load()

			if tt.expectErr != "" {
				require.Error(t, err, "a prefix that breaks decryption must not start the proxy")
				assert.Contains(t, err.Error(), tt.expectErr)
				assert.Contains(t, err.Error(), "encryption.metadata_key_prefix",
					"the error must name the field the operator has to change")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg.Encryption.MetadataKeyPrefix)
			assert.Equal(t, tt.expect, *cfg.Encryption.MetadataKeyPrefix)
		})
	}
}

func TestCfgLoadExpandsEnvironmentVariables(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)
	t.Setenv("CFG_BACKEND_KEY", "expanded-backend-key")
	t.Setenv("CFG_BACKEND_SECRET", "expanded-backend-secret")
	t.Setenv("CFG_CLIENT_SECRET", "expanded-client-secret")
	t.Setenv("CFG_AES_KEY", CfgTestAESKey)

	body := `
s3_backend:
  target_endpoint: "https://minio:9000"
  access_key_id: "${CFG_BACKEND_KEY}"
  secret_key: "${CFG_BACKEND_SECRET}"
encryption:
  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
    - alias: "aes-legacy"
      type: "aes"
      config:
        aes_key: "${CFG_AES_KEY}"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "${CFG_CLIENT_SECRET}"
`
	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
	InitConfig(path)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "expanded-backend-key", cfg.S3Backend.AccessKeyID)
	assert.Equal(t, "expanded-backend-secret", cfg.S3Backend.SecretKey)
	assert.Equal(t, "expanded-client-secret", cfg.S3Clients[0].SecretKey)
	assert.Equal(t, CfgTestAESKey, cfg.Encryption.Providers[1].Config["aes_key"])
}

func TestCfgLoadFailsOnUnsetEnvironmentVariable(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)

	body := `
s3_backend:
  target_endpoint: "https://minio:9000"
  secret_key: "${CFG_DEFINITELY_UNSET_SECRET}"
encryption:
  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`
	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
	InitConfig(path)

	cfg, err := Load()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "environment variable expansion failed")
	assert.Contains(t, err.Error(), "s3_backend.secret_key")
	assert.Contains(t, err.Error(), "${CFG_DEFINITELY_UNSET_SECRET} is not set or empty")
}

func TestCfgLoadFailsOnUnmarshalError(t *testing.T) {
	CfgResetViper(t)
	setDefaults()
	viper.Set("s3_backend.target_endpoint", "https://minio:9000")
	viper.Set("optimizations.streaming_segment_size", "twelve-megabytes")

	cfg, err := Load()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to unmarshal config")
	assert.Contains(t, err.Error(), "optimizations.streaming_segment_size")
}

func TestCfgLoadFailsOnValidationError(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)
	setDefaults()
	viper.Set("s3_backend.target_endpoint", "https://minio:9000")
	viper.Set("encryption.encryption_method_alias", "way-out")
	viper.Set("encryption.providers", []map[string]interface{}{
		{"alias": "way-out", "type": "exit", "config": map[string]interface{}{}},
	})
	// No s3_clients at all.

	cfg, err := Load()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "config validation failed")
	assert.Contains(t, err.Error(), "s3_clients configuration is required")
}

func TestCfgLoadFailsWhenProvidersAreNotASequence(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)

	body := `
s3_backend:
  target_endpoint: "https://minio:9000"
encryption:
  encryption_method_alias: "way-out"
  providers:
    alias: "way-out"
    type: "exit"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`
	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
	InitConfig(path)

	cfg, err := Load()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "provider config loading failed")
	assert.Contains(t, err.Error(), "providers data is not a recognized format")
}

func TestCfgLoadProviderConfigsWithoutProviders(t *testing.T) {
	CfgResetViper(t)
	setDefaults()

	cfg := &Config{
		Encryption: EncryptionConfig{
			Providers: []EncryptionProvider{{Alias: "stale", Type: "exit"}},
		},
	}

	require.NoError(t, loadProviderConfigs(cfg))
	// Nothing is configured, so the pre-existing slice is left untouched.
	assert.Len(t, cfg.Encryption.Providers, 1)
}

func TestCfgLoadProvidersFromInterfaceSliceRejectsNonMapEntry(t *testing.T) {
	CfgResetViper(t)
	setDefaults()
	viper.Set("encryption.providers", []interface{}{
		map[string]interface{}{"alias": "ok", "type": "exit"},
		"this-is-not-a-map",
	})

	cfg := &Config{}
	err := loadProviderConfigs(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider 1 is not a map")
	assert.Nil(t, cfg.Encryption.Providers)
}

func TestCfgLoadProvidersFromMapSlice(t *testing.T) {
	CfgResetViper(t)
	setDefaults()
	viper.Set("encryption.providers", []map[string]interface{}{
		{"alias": "a", "type": "exit", "description": "first"},
		{"alias": "b", "type": "aes", "config": map[string]interface{}{"aes_key": CfgTestAESKey}},
	})

	cfg := &Config{}
	require.NoError(t, loadProviderConfigs(cfg))
	require.Len(t, cfg.Encryption.Providers, 2)
	assert.Equal(t, "first", cfg.Encryption.Providers[0].Description)
	assert.Equal(t, CfgTestAESKey, cfg.Encryption.Providers[1].Config["aes_key"])
}

func TestCfgCreateProviderFromProviderMap(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]interface{}
		expectAlias string
		expectType  string
		expectDesc  string
		expectCfg   map[string]interface{}
	}{
		{
			name:      "empty map yields an empty provider with an initialised config",
			input:     map[string]interface{}{},
			expectCfg: map[string]interface{}{},
		},
		{
			name: "all fields are mapped",
			input: map[string]interface{}{
				"alias":       "a",
				"type":        "aes",
				"description": "d",
				"config":      map[string]interface{}{"aes_key": CfgTestAESKey},
			},
			expectAlias: "a",
			expectType:  "aes",
			expectDesc:  "d",
			expectCfg:   map[string]interface{}{"aes_key": CfgTestAESKey},
		},
		{
			name: "non string basic fields are ignored",
			input: map[string]interface{}{
				"alias":       42,
				"type":        true,
				"description": []string{"x"},
			},
			expectCfg: map[string]interface{}{},
		},
		{
			name: "a config value that is not a map is silently dropped",
			input: map[string]interface{}{
				"alias":  "a",
				"type":   "aes",
				"config": "aes_key=secret",
			},
			expectAlias: "a",
			expectType:  "aes",
			expectCfg:   map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := createProviderFromProviderMap(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expectAlias, provider.Alias)
			assert.Equal(t, tt.expectType, provider.Type)
			assert.Equal(t, tt.expectDesc, provider.Description)
			assert.Equal(t, tt.expectCfg, provider.Config)
		})
	}
}

func TestCfgLoadAndStartLicenseWithoutLicense(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)

	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", CfgMinimalYAML)
	InitConfig(path)
	viper.Set("license_file", filepath.Join(t.TempDir(), "absent.jwt"))

	cfg, validator, err := LoadAndStartLicense()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, validator)
	// NOTE: validator.Stop() is deliberately not called here - it blocks forever
	// when runtime monitoring was never started (see the defect report).

	assert.Equal(t, "https://minio:9000", cfg.S3Backend.TargetEndpoint)
	// Without a valid license only the exit provider is permitted.
	assert.Error(t, validator.ValidateProviderType("aes"))
	assert.NoError(t, validator.ValidateProviderType("exit"))
}

func TestCfgLoadAndStartLicensePropagatesLoadError(t *testing.T) {
	CfgResetViper(t)
	CfgNoLicense(t)
	setDefaults()
	// No target endpoint configured at all.

	cfg, validator, err := LoadAndStartLicense()
	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Nil(t, validator)
	assert.Contains(t, err.Error(), "target_endpoint is required")
}

// ADR 0013 D11. A key this version does not define refuses the start, and the
// refusal names it. It is the only mechanism that makes a removed key visible to
// an operator upgrading: without it the key is dropped in silence and the setting
// they believe is in force is not.
func TestCfgUnknownKeyRefusesTheStart(t *testing.T) {
	CfgNoLicense(t)

	// %s marks where a key under `encryption:` goes; extraTopLevel is appended
	// to the document. Two seams, because a removed key can sit at either depth
	// and a second top-level `encryption:` would replace the first one.
	base := `
s3_backend:
  target_endpoint: "https://minio:9000"
encryption:
%s  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`

	tests := []struct {
		name          string
		underEncrypt  string
		extraTopLevel string
		wantNamed     string
	}{
		{name: "the base configuration loads"},
		{
			// The shape an operator upgrading from 4.x arrives with.
			name:         "a key this release removed",
			underEncrypt: "  integrity_verification: \"strict\"\n",
			wantNamed:    "integrity_verification",
		},
		{
			name:          "a misspelled key",
			extraTopLevel: "shutdown_timout: 30\n",
			wantNamed:     "shutdown_timout",
		},
		{
			name:          "a removed top-level backend key",
			extraTopLevel: "target_endpoint: \"https://minio:9000\"\n",
			wantNamed:     "target_endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CfgResetViper(t)
			body := fmt.Sprintf(base, tt.underEncrypt) + tt.extraTopLevel
			path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
			InitConfig(path)

			_, err := Load()
			if tt.wantNamed == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantNamed,
				"the refusal must name the key, or the operator cannot act on it")
		})
	}
}

// The first boundary of ADR 0013 D11: a provider block keeps swallowing its own
// parameters, because EncryptionProvider carries a `,remain` field and
// mapstructure clears the unused-key set before it applies the unknown-key check.
// Asserted rather than assumed — every provider type would break at once.
//
// The exit provider is the subject on purpose: it needs no licence, so this tests
// the decoding boundary and nothing else.
func TestCfgProviderParametersAreNotUnknownKeys(t *testing.T) {
	CfgNoLicense(t)
	CfgResetViper(t)

	body := `
s3_backend:
  target_endpoint: "https://minio:9000"
encryption:
  encryption_method_alias: "way-out"
  providers:
    - alias: "way-out"
      type: "exit"
      description: "a description nothing reads"
      config:
        a_parameter_no_struct_field_declares: "value"
s3_clients:
  - type: "static"
    access_key_id: "clientkey01"
    secret_key: "0123456789abcdef"
`
	path := CfgWriteConfigFile(t, t.TempDir(), "proxy.yaml", body)
	InitConfig(path)

	cfg, err := Load()
	require.NoError(t, err, "a provider's own parameters must not read as unknown keys")
	require.Len(t, cfg.Encryption.Providers, 1)
	assert.Equal(t, "value", cfg.Encryption.Providers[0].Config["a_parameter_no_struct_field_declares"])
}

// Every configuration this repository ships has to survive the unknown-key
// refusal of ADR 0013 D11, and a shipped file that does not is a release defect
// rather than a test failure. Only the decode stage is exercised: the aes
// examples need a licence to pass full validation, and the licence is not what
// this is about.
func TestCfgShippedExamplesCarryNoUnknownKeys(t *testing.T) {
	CfgNoLicense(t)

	matches, err := filepath.Glob(filepath.Join("..", "..", "config", "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, matches, "the shipped example configurations must be found")

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			CfgResetViper(t)
			InitConfig(path)
			require.NoError(t, viper.ReadInConfig())

			var cfg Config
			err := viper.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
				dc.ErrorUnused = true
			})
			require.NoError(t, err,
				"%s carries a key no code reads; it would refuse the start", filepath.Base(path))
		})
	}
}
