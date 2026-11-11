// Package storedobject is what an object of the stored format looks like at the
// backend apart from its bytes: the metadata that names the format and carries
// the wrapped data key, the namespace that metadata lives in, and the stored
// length a ranged answer reports.
//
// The proxy and the client library build and read objects through this package
// alone, so the two cannot disagree on a key name, on the namespace rule or on
// how a new object is keyed (ADR 0009, ADR 0041).
package storedobject

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
)

// DefaultPrefix is the metadata prefix when the configuration names none.
const DefaultPrefix = "s3ep-"

// The four metadata keys the format writes under the prefix, and nothing else
// (ADR 0009).
const (
	KeyEncryptedDEK   = "encrypted-dek"
	KeyDEKAlgorithm   = "dek-algorithm"
	KeyKEKFingerprint = "kek-fingerprint"
	KeyKEKAlgorithm   = "kek-algorithm"
)

// dekSize is the length of the data key drawn for every object: AES-256.
const dekSize = 32

// PrefixPattern is what a metadata prefix must match (ADR 0009 D2).
//
// Lowercase, because S3 lower-cases metadata keys in transit: a prefix with a
// capital in it never matches on the way back, which disables decryption and
// leaks the encryption metadata to the client. Non-empty, because an empty
// prefix stores "encrypted-dek" unprefixed, inside the namespace a client can
// write. At least four characters ending in a dash, so the namespace stays
// separable from a client key that merely begins with the same letters.
var PrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,}-$`)

var (
	// ErrNoWrappedDEK marks metadata that names the format but carries no
	// readable wrapped data key.
	ErrNoWrappedDEK = errors.New("encrypted DEK not found in metadata")

	// ErrNoFingerprint marks metadata that names the format but no key
	// encryption key fingerprint.
	ErrNoFingerprint = errors.New("KEK fingerprint not found in metadata")
)

// IsReserved reports whether a metadata key lies inside the prefix's namespace.
// The comparison ignores case: net/http canonicalises header names, so a client
// header x-amz-meta-s3ep-encrypted-dek arrives as X-Amz-Meta-S3ep-Encrypted-Dek,
// and a prefix is lowercase by PrefixPattern.
func IsReserved(prefix, key string) bool {
	return strings.HasPrefix(strings.ToLower(key), prefix)
}

// UserMetadata is the stored metadata without the format's namespace, or nil
// when nothing is left.
func UserMetadata(prefix string, stored map[string]string) map[string]string {
	var out map[string]string
	for k, v := range stored {
		if IsReserved(prefix, k) {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(stored))
		}
		out[k] = v
	}
	return out
}

// Metadata builds what a write stores: the caller's metadata plus the four
// format keys. A caller key inside the namespace is dropped here as well as
// refused where user metadata is collected, so no caller can place a key that a
// read would then find beside the four this function writes (ADR 0009 D6).
func Metadata(prefix string, wrappedDEK []byte, fingerprint, kekAlgorithm string, user map[string]string) map[string]string {
	md := make(map[string]string, len(user)+4)
	for k, v := range user {
		if !IsReserved(prefix, k) {
			md[k] = v
		}
	}
	md[prefix+KeyEncryptedDEK] = base64.StdEncoding.EncodeToString(wrappedDEK)
	md[prefix+KeyDEKAlgorithm] = dataencryption.FormatID
	md[prefix+KeyKEKFingerprint] = fingerprint
	md[prefix+KeyKEKAlgorithm] = kekAlgorithm
	return md
}

// New draws a data key for one object, wraps it with kek and returns the codec
// that seals the object together with the metadata to store beside it. The data
// key is cleared before New returns: the codec holds it only as an expanded
// cipher schedule.
func New(
	ctx context.Context, kek encryption.KeyEncryptor, prefix, objectKey string, user map[string]string,
) (*dataencryption.Codec, map[string]string, error) {
	dek := make([]byte, dekSize)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	codec, err := dataencryption.NewCodec(dek, objectKey)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := kek.EncryptDEK(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap data key: %w", err)
	}
	return codec, Metadata(prefix, wrapped, kek.Fingerprint(), kek.Name(), user), nil
}

// ClaimsFormat reports whether the metadata names this format, whatever the
// state of the wrapped data key. Only the prefixed key is read: the unprefixed
// name lies outside the namespace, where a client can set it (ADR 0009 D1).
func ClaimsFormat(prefix string, md map[string]string) bool {
	return md[prefix+KeyDEKAlgorithm] == dataencryption.FormatID
}

// WrappedDEK returns the object's wrapped data key.
func WrappedDEK(prefix string, md map[string]string) ([]byte, error) {
	encoded, ok := md[prefix+KeyEncryptedDEK]
	if !ok {
		return nil, ErrNoWrappedDEK
	}
	wrapped, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(wrapped) == 0 {
		return nil, fmt.Errorf("%w: the stored value is not base64 of a wrapped key", ErrNoWrappedDEK)
	}
	return wrapped, nil
}

// Fingerprint returns the fingerprint of the key encryption key the object
// names. It selects the key that unwraps the data key.
func Fingerprint(prefix string, md map[string]string) (string, error) {
	fingerprint, ok := md[prefix+KeyKEKFingerprint]
	if !ok {
		return "", ErrNoFingerprint
	}
	return fingerprint, nil
}

// KEKAlgorithm reports which key encryption algorithm the object says wrapped
// its data key, or "" when it says nothing. It is diagnostics, not a decision:
// the key is selected by the fingerprint, and this field is unauthenticated
// (ADR 0002 D14).
func KEKAlgorithm(prefix string, md map[string]string) string {
	return md[prefix+KeyKEKAlgorithm]
}

// TotalFromContentRange reads the complete stored length from the Content-Range
// of a ranged answer, "bytes first-last/total". The read paths ask for an
// object's last bytes and check the trailer against this number.
func TotalFromContentRange(contentRange string) (int64, error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(contentRange), "bytes ")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	_, totalStr, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	total, err := strconv.ParseInt(strings.TrimSpace(totalStr), 10, 64)
	if err != nil || total < 0 {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	return total, nil
}
