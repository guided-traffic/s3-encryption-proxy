package validation

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// ValnewCfg builds a minimal config carrying only the integrity verification mode.
func ValnewCfg(mode string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification: mode,
		},
	}
}

// ValdigestOf returns the hex SHA-256 digest of b, used to compare large buffers
// without dumping them.
func ValdigestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestValNewHMACManagerWithoutConfig(t *testing.T) {
	manager := NewHMACManagerWithoutConfig()

	require.NotNil(t, manager)
	require.NotNil(t, manager.logger)
	assert.Equal(t, "hmac_manager", manager.logger.Data["component"])
	assert.Nil(t, manager.config)

	// Without config the manager must fail closed for the enablement flags but
	// still report a well defined mode.
	assert.False(t, manager.IsEnabled())
	assert.False(t, manager.ShouldCreateHMAC())
	assert.Equal(t, config.HMACVerificationOff, manager.GetIntegrityMode())
	assert.False(t, manager.ShouldVerifyHMAC(true))
}

func TestValHMACManagerSetConfig(t *testing.T) {
	manager := NewHMACManagerWithoutConfig()
	require.Equal(t, config.HMACVerificationOff, manager.GetIntegrityMode())
	require.False(t, manager.IsEnabled())

	manager.SetConfig(ValnewCfg(config.HMACVerificationStrict))
	assert.Equal(t, config.HMACVerificationStrict, manager.GetIntegrityMode())
	assert.True(t, manager.IsEnabled())
	assert.True(t, manager.ShouldCreateHMAC())

	// Swapping the config back must take effect immediately.
	manager.SetConfig(ValnewCfg(config.HMACVerificationOff))
	assert.Equal(t, config.HMACVerificationOff, manager.GetIntegrityMode())
	assert.False(t, manager.IsEnabled())
	assert.False(t, manager.ShouldCreateHMAC())

	// A nil config resets the manager to the fail-closed default.
	manager.SetConfig(nil)
	assert.Nil(t, manager.config)
	assert.Equal(t, config.HMACVerificationOff, manager.GetIntegrityMode())
	assert.False(t, manager.IsEnabled())
}

func TestValHMACManagerModeFlags(t *testing.T) {
	tests := []struct {
		name              string
		cfg               *config.Config
		expectedMode      string
		expectEnabled     bool
		expectCreate      bool
		expectVerifyWith  bool
		expectVerifyEmpty bool
	}{
		{
			name:              "nil config",
			cfg:               nil,
			expectedMode:      config.HMACVerificationOff,
			expectEnabled:     false,
			expectCreate:      false,
			expectVerifyWith:  false,
			expectVerifyEmpty: false,
		},
		{
			name:              "off",
			cfg:               ValnewCfg(config.HMACVerificationOff),
			expectedMode:      config.HMACVerificationOff,
			expectEnabled:     false,
			expectCreate:      false,
			expectVerifyWith:  false,
			expectVerifyEmpty: false,
		},
		{
			name:              "lax",
			cfg:               ValnewCfg(config.HMACVerificationLax),
			expectedMode:      config.HMACVerificationLax,
			expectEnabled:     true,
			expectCreate:      true,
			expectVerifyWith:  true,
			expectVerifyEmpty: false,
		},
		{
			name:              "strict",
			cfg:               ValnewCfg(config.HMACVerificationStrict),
			expectedMode:      config.HMACVerificationStrict,
			expectEnabled:     true,
			expectCreate:      true,
			expectVerifyWith:  true,
			expectVerifyEmpty: false,
		},
		{
			// Hybrid deliberately behaves like strict for the flags: it only
			// differs inside VerifyIntegrity, where a missing HMAC is accepted.
			name:              "hybrid",
			cfg:               ValnewCfg(config.HMACVerificationHybrid),
			expectedMode:      config.HMACVerificationHybrid,
			expectEnabled:     true,
			expectCreate:      true,
			expectVerifyWith:  true,
			expectVerifyEmpty: false,
		},
		{
			// Defensive branch: config validation normalises "" to "off" and
			// rejects anything else, so this state is only reachable through a
			// hand-built Config. Note the inconsistency it exposes: IsEnabled
			// tests "!= off" and therefore reports true, while ShouldVerifyHMAC
			// falls through to its default and reports false - HMACs would be
			// written on upload but never verified on download.
			name:              "unknown mode is enabled for writes but never verified",
			cfg:               ValnewCfg("bogus-mode"),
			expectedMode:      "bogus-mode",
			expectEnabled:     true,
			expectCreate:      true,
			expectVerifyWith:  false,
			expectVerifyEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewHMACManager(tt.cfg)

			assert.Equal(t, tt.expectedMode, manager.GetIntegrityMode())
			assert.Equal(t, tt.expectEnabled, manager.IsEnabled())
			assert.Equal(t, tt.expectCreate, manager.ShouldCreateHMAC())
			assert.Equal(t, tt.expectVerifyWith, manager.ShouldVerifyHMAC(true))
			assert.Equal(t, tt.expectVerifyEmpty, manager.ShouldVerifyHMAC(false))
		})
	}
}

// TestValHMACManagerVerifyIntegrityWeakModes pins the two behaviours the
// documentation calls out as deliberate weaknesses. Ticket 013 / finding N-2
// changes both of them; until then these assertions describe the shipped
// behaviour so an accidental change is caught, and a deliberate change forces
// this test to be updated together with the code.
func TestValHMACManagerVerifyIntegrityWeakModes(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, 32)
	payload := []byte("payload that gets its HMAC checked")

	newCalc := func(t *testing.T, manager *HMACManager) *HMACCalculator {
		t.Helper()
		calc, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = calc.Add(payload)
		require.NoError(t, err)
		return calc
	}

	t.Run("lax delivers despite a mismatching HMAC", func(t *testing.T) {
		// Ticket 013 / N-2: lax swallows a real integrity failure and serves
		// possibly tampered data. Pinned, not endorsed.
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationLax))
		calc := newCalc(t, manager)

		wrong := bytes.Repeat([]byte{0xFF}, sha256.Size)
		require.NoError(t, manager.VerifyIntegrity(calc, wrong),
			"lax mode must currently return nil on mismatch")
	})

	t.Run("hybrid accepts a missing HMAC as a legacy object", func(t *testing.T) {
		// Ticket 013 / N-2: an attacker who can strip the HMAC metadata
		// downgrades verification to none. Pinned, not endorsed.
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationHybrid))

		calc := newCalc(t, manager)
		require.NoError(t, manager.VerifyIntegrity(calc, nil),
			"hybrid mode must currently accept a nil HMAC")

		calc = newCalc(t, manager)
		require.NoError(t, manager.VerifyIntegrity(calc, []byte{}),
			"hybrid mode must currently accept an empty HMAC")
	})

	t.Run("strict rejects a missing HMAC", func(t *testing.T) {
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationStrict))
		calc := newCalc(t, manager)

		err := manager.VerifyIntegrity(calc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected HMAC is empty")
	})

	t.Run("lax also rejects a missing HMAC", func(t *testing.T) {
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationLax))
		calc := newCalc(t, manager)

		err := manager.VerifyIntegrity(calc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected HMAC is empty")
	})

	t.Run("off skips verification entirely", func(t *testing.T) {
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationOff))
		calc := newCalc(t, manager)

		require.NoError(t, manager.VerifyIntegrity(calc, bytes.Repeat([]byte{0x00}, sha256.Size)))
		require.NoError(t, manager.VerifyIntegrity(calc, nil))

		// Off mode returns before finalising, so the calculator is untouched and
		// still holds its key material.
		assert.NotNil(t, calc.GetCurrentHash())
	})

	t.Run("unknown mode fails closed on mismatch", func(t *testing.T) {
		// Default branch of the failure switch: anything that is not lax must
		// abort delivery.
		manager := NewHMACManager(ValnewCfg("bogus-mode"))
		calc := newCalc(t, manager)

		err := manager.VerifyIntegrity(calc, bytes.Repeat([]byte{0xAB}, sha256.Size))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data integrity compromised")
	})

	t.Run("nil calculator is rejected in every mode", func(t *testing.T) {
		for _, mode := range []string{
			config.HMACVerificationOff,
			config.HMACVerificationLax,
			config.HMACVerificationStrict,
			config.HMACVerificationHybrid,
		} {
			manager := NewHMACManager(ValnewCfg(mode))
			err := manager.VerifyIntegrity(nil, bytes.Repeat([]byte{0x01}, sha256.Size))
			require.Error(t, err, "mode %s", mode)
			assert.Contains(t, err.Error(), "HMAC calculator is nil", "mode %s", mode)
		}
	})

	t.Run("already cleaned calculator cannot produce an HMAC", func(t *testing.T) {
		manager := NewHMACManager(ValnewCfg(config.HMACVerificationStrict))
		calc := newCalc(t, manager)
		expected := calc.GetCurrentHash()

		calc.Cleanup()

		err := manager.VerifyIntegrity(calc, expected)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to compute HMAC from calculator")
	})
}

func TestValHMACManagerRoundTripAndTampering(t *testing.T) {
	dek := bytes.Repeat([]byte{0x9B}, 32)
	manager := NewHMACManager(ValnewCfg(config.HMACVerificationStrict))

	// 1 MiB of non-repeating data so a chunk boundary bug cannot hide.
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}

	// Upload side: HMAC computed over the object in segments.
	writer, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	for offset := 0; offset < len(plaintext); offset += 7919 { // prime-sized segments
		end := offset + 7919
		if end > len(plaintext) {
			end = len(plaintext)
		}
		n, err := writer.Add(plaintext[offset:end])
		require.NoError(t, err)
		require.Equal(t, end-offset, n)
	}
	storedHMAC := manager.FinalizeCalculator(writer)
	require.Len(t, storedHMAC, sha256.Size)

	// The stored HMAC must equal a plain crypto/hmac over the whole buffer with
	// the HKDF-derived key - the same value another implementation would get.
	hmacKey, err := DeriveIntegrityKey(dek)
	require.NoError(t, err)
	reference := hmac.New(sha256.New, hmacKey)
	_, err = reference.Write(plaintext)
	require.NoError(t, err)
	assert.Equal(t, ValdigestOf(reference.Sum(nil)), ValdigestOf(storedHMAC))

	t.Run("untampered download verifies", func(t *testing.T) {
		reader, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = reader.AddFromStream(bufio.NewReader(bytes.NewReader(plaintext)))
		require.NoError(t, err)
		require.NoError(t, manager.VerifyIntegrity(reader, storedHMAC))
	})

	t.Run("a single flipped bit is detected", func(t *testing.T) {
		tampered := append([]byte(nil), plaintext...)
		tampered[len(tampered)/2] ^= 0x01
		require.NotEqual(t, ValdigestOf(plaintext), ValdigestOf(tampered))

		reader, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = reader.AddFromStream(bufio.NewReader(bytes.NewReader(tampered)))
		require.NoError(t, err)

		err = manager.VerifyIntegrity(reader, storedHMAC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data integrity compromised")
	})

	t.Run("truncation is detected", func(t *testing.T) {
		reader, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = reader.AddFromStream(bufio.NewReader(bytes.NewReader(plaintext[:len(plaintext)-1])))
		require.NoError(t, err)

		err = manager.VerifyIntegrity(reader, storedHMAC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data integrity compromised")
	})

	t.Run("a wrong DEK does not verify", func(t *testing.T) {
		wrongDEK := append([]byte(nil), dek...)
		wrongDEK[0] ^= 0x01

		reader, err := manager.CreateCalculator(wrongDEK)
		require.NoError(t, err)
		_, err = reader.Add(plaintext)
		require.NoError(t, err)

		err = manager.VerifyIntegrity(reader, storedHMAC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data integrity compromised")
	})

	t.Run("a truncated expected HMAC does not verify", func(t *testing.T) {
		// hmac.Equal is length sensitive: a prefix of the correct HMAC must be
		// rejected rather than accepted as a partial match.
		reader, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = reader.Add(plaintext)
		require.NoError(t, err)

		err = manager.VerifyIntegrity(reader, storedHMAC[:16])
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data integrity compromised")
	})

	t.Run("segmented and streamed reads agree", func(t *testing.T) {
		streamed, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = streamed.AddFromStream(bufio.NewReader(bytes.NewReader(plaintext)))
		require.NoError(t, err)

		single, err := manager.CreateCalculator(dek)
		require.NoError(t, err)
		_, err = single.Add(plaintext)
		require.NoError(t, err)

		assert.Equal(t, ValdigestOf(streamed.GetCurrentHash()), ValdigestOf(single.GetCurrentHash()))
	})
}

func TestValHMACManagerClearSensitiveData(t *testing.T) {
	manager := NewHMACManagerWithoutConfig()

	t.Run("zeroes the backing array in place", func(t *testing.T) {
		secret := bytes.Repeat([]byte{0xFE}, 48)
		alias := secret // shares the backing array

		manager.ClearSensitiveData(secret)

		assert.Equal(t, bytes.Repeat([]byte{0x00}, 48), secret)
		assert.Equal(t, bytes.Repeat([]byte{0x00}, 48), alias,
			"clearing must affect the shared backing array, not a copy")
	})

	t.Run("handles nil and empty slices", func(t *testing.T) {
		assert.NotPanics(t, func() { manager.ClearSensitiveData(nil) })
		assert.NotPanics(t, func() { manager.ClearSensitiveData([]byte{}) })
	})

	t.Run("only clears the slice it is given", func(t *testing.T) {
		buf := bytes.Repeat([]byte{0x11}, 8)
		manager.ClearSensitiveData(buf[2:5])

		assert.Equal(t, []byte{0x11, 0x11, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11}, buf)
	})
}

func TestValHMACManagerFinalizeCalculatorClearsKey(t *testing.T) {
	manager := NewHMACManagerWithoutConfig()
	dek := bytes.Repeat([]byte{0x5F}, 32)

	calc, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calc.Add([]byte("finalize me"))
	require.NoError(t, err)

	value := manager.FinalizeCalculator(calc)
	require.Len(t, value, sha256.Size)

	// Finalize must leave the calculator unusable and the key material gone.
	assert.Nil(t, calc.hmacKey)
	assert.Nil(t, calc.calculator)
	assert.Nil(t, calc.GetCurrentHash())

	_, err = calc.Add([]byte("more"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC calculator not initialized")

	// Finalizing twice must not panic and must report nil.
	assert.Nil(t, manager.FinalizeCalculator(nil))
}
