package middleware

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Query parameters of a pre-signed AWS Signature V4 request.
const (
	QueryAlgorithm     = "X-Amz-Algorithm"
	QueryCredential    = "X-Amz-Credential"
	QueryDate          = "X-Amz-Date"
	QueryExpires       = "X-Amz-Expires"
	QuerySignedHeaders = "X-Amz-SignedHeaders"
	QuerySignature     = "X-Amz-Signature"
	QuerySecurityToken = "X-Amz-Security-Token"

	// maxPresignExpirySeconds is the AWS limit for a pre-signed URL: 7 days.
	maxPresignExpirySeconds = 7 * 24 * 60 * 60
)

// isPresignedRequest reports whether the request carries a query-string
// signature instead of an Authorization header.
func isPresignedRequest(r *http.Request) bool {
	return r.URL.Query().Get(QueryAlgorithm) != ""
}

// authenticatePresigned validates a query-string (pre-signed) AWS Signature V4
// request.
//
// Velero needs this: every download it performs goes through a pre-signed URL
// minted by the server and fetched by a client that holds no credentials --
// `velero backup logs`, `velero restore logs`, `velero backup download` and the
// results fetch inside `velero backup describe`. Without it those all return
// 403 even though the backup itself succeeded.
//
// Security properties, all enforced below:
//   - The signature covers the method, the path, every query parameter except
//     the signature itself, and the signed headers (host is always among them),
//     so a signed URL cannot be repointed at another object or another verb.
//   - X-Amz-Expires is mandatory, bounded to the AWS maximum of 7 days, and
//     checked against the signing time, so a leaked URL stops working.
//   - The signing time is subject to the same clock-skew window as header auth,
//     so a URL cannot be back- or post-dated into a longer life.
//
// A pre-signed URL is a bearer credential by construction: whoever holds it can
// perform exactly the one request it describes until it expires. That is the
// mechanism AWS defines and the one Velero depends on; the proxy narrows it no
// further than S3 itself does.
func (s *S3AuthenticationService) authenticatePresigned(r *http.Request) error {
	query := r.URL.Query()

	if algorithm := query.Get(QueryAlgorithm); algorithm != AWS4Algorithm {
		s.logSecurityEvent("presigned_unsupported_algorithm", r, algorithm)
		return fmt.Errorf("unsupported presigned algorithm: %s", algorithm)
	}

	credential := query.Get(QueryCredential)
	signature := query.Get(QuerySignature)
	signedHeadersRaw := query.Get(QuerySignedHeaders)
	if credential == "" || signature == "" || signedHeadersRaw == "" {
		s.logSecurityEvent("presigned_incomplete", r, "missing credential, signature or signed headers")
		return fmt.Errorf("incomplete presigned request")
	}

	sigInfo, err := parseCredentialScope(credential)
	if err != nil {
		s.logSecurityEvent("presigned_malformed_credential", r, err.Error())
		return fmt.Errorf("malformed presigned credential: %w", err)
	}
	sigInfo.SignedHeaders = strings.Split(signedHeadersRaw, ";")
	sigInfo.Signature = signature

	signedAt, err := time.Parse(ISO8601BasicFormat, query.Get(QueryDate))
	if err != nil {
		s.logSecurityEvent("presigned_invalid_date", r, query.Get(QueryDate))
		return fmt.Errorf("invalid X-Amz-Date: %w", err)
	}

	if err := s.validatePresignExpiry(signedAt, query.Get(QueryExpires)); err != nil {
		s.logSecurityEvent("presigned_expired", r, err.Error())
		return fmt.Errorf("presigned URL rejected: %w", err)
	}

	// The credential scope date must match the signing date, exactly as for
	// header auth: otherwise a signature could be replayed under a scope key
	// derived for a different day.
	if sigInfo.Date != signedAt.UTC().Format(ISO8601DateFormat) {
		s.logSecurityEvent("presigned_date_mismatch", r,
			fmt.Sprintf("%s != %s", sigInfo.Date, signedAt.UTC().Format(ISO8601DateFormat)))
		return fmt.Errorf("credential date does not match the signing date")
	}

	client, exists := s.clientCache[sigInfo.AccessKeyID]
	if !exists {
		s.logSecurityEvent("unknown_access_key", r, sigInfo.AccessKeyID)
		return fmt.Errorf("access key not found: %s", sigInfo.AccessKeyID)
	}

	canonicalRequest, err := s.buildPresignedCanonicalRequest(r, sigInfo.SignedHeaders)
	if err != nil {
		s.logSecurityEvent("presigned_canonical_request_failed", r, err.Error())
		return fmt.Errorf("failed to build canonical request: %w", err)
	}

	stringToSign := s.buildStringToSign(query.Get(QueryDate), sigInfo.CredentialScope, canonicalRequest)
	expected := s.calculateSignature(client.SecretKey, sigInfo.Date, sigInfo.Region, sigInfo.Service, stringToSign)

	if subtle.ConstantTimeCompare([]byte(sigInfo.Signature), []byte(expected)) != 1 {
		s.securityMetrics.InvalidSignatures++
		s.logSecurityEvent("signature_verification_failed", r, "presigned signature mismatch")
		return fmt.Errorf("signature verification failed: presigned signature mismatch")
	}

	s.logger.WithFields(map[string]interface{}{
		"access_key_id": sigInfo.AccessKeyID,
		"method":        r.Method,
		"path":          r.URL.Path,
		"description":   client.Description,
		"presigned":     true,
		"signed_at":     signedAt.Format(time.RFC3339),
	}).Debug("S3 client authenticated successfully via presigned URL")

	return nil
}

// validatePresignExpiry enforces the expiry window carried in the URL.
func (s *S3AuthenticationService) validatePresignExpiry(signedAt time.Time, expiresRaw string) error {
	if expiresRaw == "" {
		return fmt.Errorf("missing %s", QueryExpires)
	}
	expires, err := strconv.Atoi(expiresRaw)
	if err != nil || expires <= 0 {
		return fmt.Errorf("invalid %s: %q", QueryExpires, expiresRaw)
	}
	if expires > maxPresignExpirySeconds {
		return fmt.Errorf("%s exceeds the maximum of %d seconds", QueryExpires, maxPresignExpirySeconds)
	}

	now := time.Now().UTC()
	skew := time.Duration(s.maxClockSkewSeconds()) * time.Second

	// A URL signed in the future beyond the tolerated skew would otherwise
	// extend its own lifetime arbitrarily.
	if signedAt.After(now.Add(skew)) {
		return fmt.Errorf("signing time is in the future by more than the allowed clock skew")
	}
	if now.After(signedAt.Add(time.Duration(expires) * time.Second).Add(skew)) {
		return fmt.Errorf("URL expired at %s", signedAt.Add(time.Duration(expires)*time.Second).Format(time.RFC3339))
	}
	return nil
}

// maxClockSkewSeconds returns the configured tolerance, falling back to the AWS
// default of 15 minutes.
func (s *S3AuthenticationService) maxClockSkewSeconds() int {
	if s.config != nil && s.config.S3Security.MaxClockSkewSeconds > 0 {
		return s.config.S3Security.MaxClockSkewSeconds
	}
	return MaxClockSkewSeconds
}

// buildPresignedCanonicalRequest builds the canonical request for a pre-signed
// URL. It differs from the header form in two ways: X-Amz-Signature is excluded
// from the canonical query string, and the payload hash is UNSIGNED-PAYLOAD
// unless the client sent an explicit one.
func (s *S3AuthenticationService) buildPresignedCanonicalRequest(r *http.Request, signedHeaders []string) (string, error) {
	canonicalHeaders, err := s.buildCanonicalHeaders(r, signedHeaders)
	if err != nil {
		return "", fmt.Errorf("failed to build canonical headers: %w", err)
	}

	query := r.URL.Query()
	query.Del(QuerySignature)

	payloadHash := r.Header.Get(XAmzContentSha256)
	if payloadHash == "" {
		payloadHash = UnsignedPayload
	}

	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL.Path),
		canonicalQueryString(query),
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n"), nil
}

// parseCredentialScope splits an AWS credential into its five components and
// validates them.
func parseCredentialScope(credential string) (*SignatureInfo, error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid credential format")
	}
	accessKeyID, date, region, service, requestType := parts[0], parts[1], parts[2], parts[3], parts[4]
	if accessKeyID == "" || len(date) != 8 || service != "s3" || requestType != AWS4RequestType {
		return nil, fmt.Errorf("invalid credential components")
	}
	return &SignatureInfo{
		Algorithm:       AWS4Algorithm,
		Credential:      credential,
		AccessKeyID:     accessKeyID,
		Date:            date,
		Region:          region,
		Service:         service,
		RequestType:     requestType,
		CredentialScope: strings.Join(parts[1:], "/"),
	}, nil
}

// uriEncode percent-encodes per RFC 3986 as AWS Signature V4 requires.
//
// net/url is not usable here: QueryEscape encodes a space as "+" and escapes
// "~", both of which AWS forbids in a canonical request, and PathEscape leaves
// characters unescaped that AWS expects encoded. A signature computed with
// either differs from the client's for any key or parameter containing those
// characters, which fails as an opaque "signature mismatch".
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/':
			if encodeSlash {
				b.WriteString("%2F")
			} else {
				b.WriteByte('/')
			}
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalURI encodes the request path, keeping path separators intact.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return uriEncode(path, false)
}

// canonicalQueryString renders the query parameters in AWS canonical form:
// every name and value URI-encoded, sorted by encoded name then encoded value.
func canonicalQueryString(values url.Values) string {
	pairs := make([]string, 0, len(values))
	for key, vals := range values {
		encodedKey := uriEncode(key, true)
		for _, v := range vals {
			pairs = append(pairs, encodedKey+"="+uriEncode(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}
