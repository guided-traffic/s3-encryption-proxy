//go:build e2e

package velero

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// minute is a readability alias for scenario timeouts.
const minute = time.Minute

// sha256Hex hashes a string. The suite compares hashes rather than contents so
// a failure never prints a payload dump.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hashStringMap hashes a map deterministically: keys sorted, length-prefixed so
// no pair of maps can collide by shifting a delimiter across fields.
func hashStringMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		_, _ = h.Write([]byte(strings.Join([]string{
			itoa(len(k)), k, itoa(len(m[k])), m[k],
		}, "\x00")))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
