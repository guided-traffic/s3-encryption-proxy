package bucket

import (
	"errors"
	"net/url"
	"strconv"
)

// maxKeysLimit is the largest page S3 will return, whatever a client asks for.
// The backend this proxy runs against in development does not clamp — it echoes
// 5000 and returns everything — so the clamp is the proxy's own behaviour and a
// documented deviation from that backend.
const maxKeysLimit = 1000

// errMaxKeysInvalid is returned for a max-keys that is not a non-negative
// integer. The caller turns it into 400 InvalidArgument.
var errMaxKeysInvalid = errors.New("max-keys must be a non-negative integer")

// parseMaxKeys applies the max-keys rule: absent means the backend default,
// a value in range is forwarded verbatim (zero included, because a client
// asking for no keys is asking a real question), a larger one is clamped, and
// anything that is not a non-negative integer is refused.
func parseMaxKeys(raw string) (*int32, error) {
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return nil, errMaxKeysInvalid
	}
	if n > maxKeysLimit {
		n = maxKeysLimit
	}
	// #nosec G109,G115 -- n is bounded by 0..maxKeysLimit above.
	v := int32(n)
	return &v, nil
}

// decodeBackendValue undoes the URL encoding the proxy always asks the backend
// for. QueryUnescape rather than PathUnescape on purpose: the development
// backend encodes a space as "+", which PathUnescape would leave as a literal
// plus. A value that does not decode is passed through unchanged — the
// alternative is failing a listing over one unusual key.
func decodeBackendValue(s string) string {
	if s == "" {
		return s
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// encodeForClient re-encodes a value when the client asked for encoding-type=url,
// and returns it untouched otherwise.
func encodeForClient(s string, wanted bool) string {
	if !wanted || s == "" {
		return s
	}
	return url.QueryEscape(s)
}

// clientWantsURLEncoding reports whether the client asked for URL-encoded keys.
// S3 accepts exactly one value here.
func clientWantsURLEncoding(raw string) bool {
	return raw == "url"
}
