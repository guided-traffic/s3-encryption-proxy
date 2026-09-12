package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// The generator had no test at all, and it produces the key an operator pastes
// into a configuration, so two contracts hang on it: the output has to be a key
// the proxy accepts, and the banner has to keep the shape the documentation
// depends on.
func TestKeygenOutput(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, printKey(&out))

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 2)

	// README.md and CLAUDE.md both document `s3ep-keygen | sed -n 2p`, so the
	// key is the second line and nothing may be printed above it.
	key := lines[1]
	raw, err := base64.StdEncoding.DecodeString(key)
	require.NoError(t, err, "line 2 must be the base64 key the documentation takes")
	assert.Len(t, raw, 32, "an AES-256 key is exactly 32 bytes")

	// The same value has to be accepted where it is used, or the generator emits
	// something the proxy refuses at startup.
	_, err = keyencryption.NewAESProvider(map[string]interface{}{"aes_key": key})
	assert.NoError(t, err, "the generated key must be one the AES provider accepts")

	// Every line that offers a way to use the key offers one the proxy has.
	assert.Contains(t, out.String(), `aes_key: "`+key+`"`)
	assert.Contains(t, out.String(), "${S3EP_AES_KEY}")
	assert.NotContains(t, out.String(), "AES_ENCRYPTION_KEY",
		"no environment variable overrides a configuration key (ADR 0013)")
}

// Each run draws a new key: a generator that repeated itself would hand two
// deployments the same master key.
func TestKeygenDrawsAFreshKeyEachTime(t *testing.T) {
	var first, second bytes.Buffer
	require.NoError(t, printKey(&first))
	require.NoError(t, printKey(&second))

	assert.NotEqual(t, first.String(), second.String())
}
