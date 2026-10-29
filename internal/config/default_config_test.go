package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The configuration the container image starts with. It ships, so it is held to
// the same standard as the code: it must load, it must fail closed, and the set
// of variables it asks for is a documented interface that cannot drift silently.
const cfgDefaultPath = "../../config/default.yaml"

// cfgDefaultEnv is every variable config/default.yaml references, and the order
// is irrelevant — the assertion is the set. Changing it is changing a documented
// interface: README.md and docs/developer/configuration.md carry the same names.
var cfgDefaultEnv = map[string]string{
	"S3EP_BACKEND_ENDPOINT":      "https://minio:9000",
	"S3EP_BACKEND_REGION":        "eu-central-1",
	"S3EP_BACKEND_ACCESS_KEY_ID": "minioadmin",
	"S3EP_BACKEND_SECRET_KEY":    "minioadmin123",
	"S3EP_CLIENT_ACCESS_KEY_ID":  "username0",
	"S3EP_CLIENT_SECRET_KEY":     "a-secret-of-at-least-16",
	"S3EP_AES_KEY":               "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=",
}

func TestCfgDefaultConfigAsksForExactlyTheDocumentedVariables(t *testing.T) {
	body, err := os.ReadFile(cfgDefaultPath)
	require.NoError(t, err)

	// Only the values, never the prose: the comment block explains the mechanism
	// with a literal ${VAR}, which is not a reference the loader will resolve.
	found := map[string]bool{}
	for _, line := range regexp.MustCompile(`\r?\n`).Split(string(body), -1) {
		if regexp.MustCompile(`^\s*#`).MatchString(line) {
			continue
		}
		for _, m := range regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`).FindAllStringSubmatch(line, -1) {
			found[m[1]] = true
		}
	}

	var got, want []string
	for name := range found {
		got = append(got, name)
	}
	for name := range cfgDefaultEnv {
		want = append(want, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	assert.Equal(t, want, got,
		"the shipped configuration's variables are a documented interface; update README.md "+
			"and docs/developer/configuration.md in the same change")
}

func TestCfgDefaultConfigLoads(t *testing.T) {
	path, err := filepath.Abs(cfgDefaultPath)
	require.NoError(t, err)

	for name, value := range cfgDefaultEnv {
		t.Setenv(name, value)
	}
	CfgResetViper(t)
	require.NoError(t, InitConfig(path))

	cfg, err := Load()

	require.NoError(t, err, "the configuration the image ships with must load")
	assert.Equal(t, "https://minio:9000", cfg.Backend().TargetEndpoint)
	assert.Equal(t, "eu-central-1", cfg.Backend().Region)
	require.Len(t, cfg.S3Clients, 1)
	assert.Equal(t, "username0", cfg.S3Clients[0].AccessKeyID)
	require.Len(t, cfg.Encryption.Providers, 1)
	assert.Equal(t, "aes", cfg.Encryption.Providers[0].Type,
		"an exit provider here would start without a key and store plaintext")
	assert.Equal(t, "aes", cfg.Encryption.EncryptionMethodAlias)
}

// Every variable is mandatory by construction: ${VAR} unset or empty is a named
// startup error, so the image cannot come up half-configured — and never with an
// empty credential or an empty key.
func TestCfgDefaultConfigFailsClosedOnEveryVariable(t *testing.T) {
	path, err := filepath.Abs(cfgDefaultPath)
	require.NoError(t, err)

	for missing := range cfgDefaultEnv {
		t.Run(missing, func(t *testing.T) {
			CfgResetViper(t)
			for name, value := range cfgDefaultEnv {
				if name == missing {
					continue
				}
				t.Setenv(name, value)
			}
			t.Setenv(missing, "")

			_, err := cfgLoadFrom(t, path)

			require.Error(t, err, "%s is unset and the proxy must refuse to start", missing)
			assert.Contains(t, err.Error(), missing, "the refusal names the variable")
		})
	}
}

// cfgLoadFrom initialises viper against path and loads, so the table above reads as
// one statement per variable.
func cfgLoadFrom(t *testing.T, path string) (*Config, error) {
	t.Helper()
	require.NoError(t, InitConfig(path))
	return Load()
}

// The other shipped configurations. `config/default.yaml` is what the image
// starts with and has the tests above; the four examples are what an operator
// copies, and one of them — multi-example.yaml — was loaded by nothing at all,
// so a key the loader no longer accepts would have shipped in it (ADR 0013 D11
// makes an unknown key a startup failure).
//
// Each is loaded through the real Load(), so the assertion is "this file starts
// a proxy", not "this file parses as YAML".
const cfgExampleAESKey = "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8="

func TestCfgShippedExamplesLoad(t *testing.T) {
	examples := map[string]struct {
		path string
		env  map[string]string
		// wantErr is set for the one example that names paths only the container
		// has: it must get as far as that file and no further.
		wantErr   string
		providers int
		active    string
		activeIs  string
	}{
		"aes-example.yaml": {
			path:      "../../config/aes-example.yaml",
			env:       map[string]string{"S3EP_AES_KEY": cfgExampleAESKey},
			providers: 1, active: "aes-envelope", activeIs: "aes",
		},
		"aes-tls-example.yaml": {
			path:    "../../config/aes-tls-example.yaml",
			env:     map[string]string{"S3EP_AES_KEY": cfgExampleAESKey},
			wantErr: "TLS certificate file does not exist: /certs/public.crt",
		},
		"exit-example.yaml": {
			path:      "../../config/exit-example.yaml",
			env:       map[string]string{"S3EP_AES_KEY": cfgExampleAESKey},
			providers: 2, active: "exit", activeIs: "exit",
		},
		"multi-example.yaml": {
			path: "../../config/multi-example.yaml",
			env: map[string]string{
				"S3EP_AES_KEY":         cfgExampleAESKey,
				"S3EP_AES_KEY_RETIRED": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE=",
			},
			providers: 2, active: "aes-current", activeIs: "aes",
		},
	}

	for name, tc := range examples {
		t.Run(name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			path, err := filepath.Abs(tc.path)
			require.NoError(t, err)

			CfgResetViper(t)
			cfg, err := cfgLoadFrom(t, path)

			if tc.wantErr != "" {
				// Everything before the certificate is validated, which is the
				// whole file: the paths are the container's, and the check that
				// stops it is the last one.
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err, "a shipped example must start a proxy, not only parse")
			assert.Len(t, cfg.Encryption.Providers, tc.providers)
			assert.Equal(t, tc.active, cfg.Encryption.EncryptionMethodAlias)

			active, err := cfg.GetActiveProvider()
			require.NoError(t, err, "the active alias must name a provider that is configured")
			assert.Equal(t, tc.activeIs, active.Type)
		})
	}
}
