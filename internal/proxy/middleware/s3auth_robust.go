package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
)

const (
	// AWS Signature V4 constants
	AWS4RequestType    = "aws4_request"
	AWS4Algorithm      = "AWS4-HMAC-SHA256"
	AWS4Prefix         = "AWS4"

	// Time formats
	ISO8601BasicFormat = "20060102T150405Z"
	ISO8601DateFormat  = "20060102"

	// Headers
	AuthorizationHeader    = "Authorization"
	DateHeader            = "Date"
	XAmzDateHeader        = "X-Amz-Date"
	XAmzContentSha256     = "X-Amz-Content-Sha256"
	HostHeader            = "Host"

	// Special values
	UnsignedPayload       = "UNSIGNED-PAYLOAD"
	StreamingSignature    = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

	// Security limits
	MaxClockSkewSeconds   = 900 // 15 minutes
	MaxAuthHeaderSize     = 8192 // 8KB max authorization header
)

// S3AuthenticationService provides comprehensive S3 authentication
type S3AuthenticationService struct {
	config          *config.Config
	logger          *logrus.Logger
	clientCache     map[string]*config.S3ClientCredentials
	securityMetrics *SecurityMetrics
}

// SecurityMetrics tracks authentication security events
type SecurityMetrics struct {
	FailedAttempts    map[string]int // IP -> count
	InvalidSignatures int
	ClockSkewErrors   int
	ReplayAttempts    int
}

// SignatureInfo contains parsed AWS signature information
type SignatureInfo struct {
	Algorithm       string
	Credential      string
	AccessKeyID     string
	Date            string
	Region          string
	Service         string
	RequestType     string
	SignedHeaders   []string
	Signature       string
	PayloadHash     string
	Timestamp       time.Time
	CredentialScope string
}

// NewS3AuthenticationService creates a secure S3 authentication service
func NewS3AuthenticationService(cfg *config.Config, logger *logrus.Logger) *S3AuthenticationService {
	service := &S3AuthenticationService{
		config:      cfg,
		logger:      logger,
		clientCache: make(map[string]*config.S3ClientCredentials),
		securityMetrics: &SecurityMetrics{
			FailedAttempts: make(map[string]int),
		},
	}

	// Build client cache for O(1) lookups
	for i := range cfg.S3Clients {
		client := &cfg.S3Clients[i]
		service.clientCache[client.AccessKeyID] = client
	}

	return service
}

// AuthenticateRequest performs comprehensive S3 request authentication
func (s *S3AuthenticationService) AuthenticateRequest(r *http.Request) error {
	// Security check: Authorization header size limit
	authHeader := r.Header.Get(AuthorizationHeader)
	if len(authHeader) > MaxAuthHeaderSize {
		s.logSecurityEvent("oversized_auth_header", r, "Authorization header exceeds size limit")
		return fmt.Errorf("authorization header too large")
	}

	// Extract and validate signature information
	sigInfo, err := s.parseAuthorizationHeader(authHeader)
	if err != nil {
		s.logSecurityEvent("malformed_auth_header", r, err.Error())
		return fmt.Errorf("malformed authorization header: %w", err)
	}

	// Security check: Clock skew protection
	if err := s.validateTimestamp(sigInfo.Timestamp, r); err != nil {
		s.securityMetrics.ClockSkewErrors++
		s.logSecurityEvent("clock_skew_error", r, err.Error())
		return fmt.Errorf("timestamp validation failed: %w", err)
	}

	// Lookup client credentials
	client, exists := s.clientCache[sigInfo.AccessKeyID]
	if !exists {
		s.logSecurityEvent("unknown_access_key", r, sigInfo.AccessKeyID)
		return fmt.Errorf("access key not found: %s", sigInfo.AccessKeyID)
	}

	// Validate signature
	if err := s.validateSignature(r, sigInfo, client.SecretKey); err != nil {
		s.securityMetrics.InvalidSignatures++
		s.logSecurityEvent("signature_verification_failed", r, err.Error())
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Log successful authentication
	s.logger.WithFields(logrus.Fields{
		"access_key_id": sigInfo.AccessKeyID,
		"method":        r.Method,
		"path":          r.URL.Path,
		"description":   client.Description,
		"timestamp":     sigInfo.Timestamp.Format(time.RFC3339),
	}).Debug("S3 client authenticated successfully")

	return nil
}

// parseAuthorizationHeader parses AWS4-HMAC-SHA256 authorization header
func (s *S3AuthenticationService) parseAuthorizationHeader(authHeader string) (*SignatureInfo, error) {
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, AWS4Algorithm+" ") {
		return nil, fmt.Errorf("unsupported authorization algorithm")
	}

	// Parse components using regex for security
	credentialRegex := regexp.MustCompile(`Credential=([^,\s]+)`)
	signedHeadersRegex := regexp.MustCompile(`SignedHeaders=([^,\s]+)`)
	signatureRegex := regexp.MustCompile(`Signature=([a-fA-F0-9]+)`)

	credentialMatch := credentialRegex.FindStringSubmatch(authHeader)
	signedHeadersMatch := signedHeadersRegex.FindStringSubmatch(authHeader)
	signatureMatch := signatureRegex.FindStringSubmatch(authHeader)

	if len(credentialMatch) < 2 || len(signedHeadersMatch) < 2 || len(signatureMatch) < 2 {
		return nil, fmt.Errorf("incomplete authorization header components")
	}

	credential := credentialMatch[1]
	signedHeaders := strings.Split(signedHeadersMatch[1], ";")
	signature := signatureMatch[1]

	// Parse credential scope: AccessKeyID/Date/Region/Service/aws4_request
	credentialParts := strings.Split(credential, "/")
	if len(credentialParts) != 5 {
		return nil, fmt.Errorf("invalid credential format")
	}

	// Security validation: Check credential components
	accessKeyID := credentialParts[0]
	date := credentialParts[1]
	region := credentialParts[2]
	service := credentialParts[3]
	requestType := credentialParts[4]

	if len(accessKeyID) == 0 || len(date) != 8 || service != "s3" || requestType != AWS4RequestType {
		return nil, fmt.Errorf("invalid credential components")
	}

	// Parse timestamp from date
	timestamp, err := time.Parse(ISO8601DateFormat, date)
	if err != nil {
		return nil, fmt.Errorf("invalid credential date format: %w", err)
	}

	credentialScope := strings.Join(credentialParts[1:], "/")

	return &SignatureInfo{
		Algorithm:       AWS4Algorithm,
		Credential:      credential,
		AccessKeyID:     accessKeyID,
		Date:            date,
		Region:          region,
		Service:         service,
		RequestType:     requestType,
		SignedHeaders:   signedHeaders,
		Signature:       signature,
		Timestamp:       timestamp,
		CredentialScope: credentialScope,
	}, nil
}

// validateTimestamp checks for clock skew and potential replay attacks
func (s *S3AuthenticationService) validateTimestamp(credentialTime time.Time, r *http.Request) error {
	now := time.Now().UTC()

	// Get request timestamp from headers
	var requestTime time.Time
	var err error

	// Prefer X-Amz-Date over Date header
	if amzDate := r.Header.Get(XAmzDateHeader); amzDate != "" {
		requestTime, err = time.Parse(ISO8601BasicFormat, amzDate)
		if err != nil {
			return fmt.Errorf("invalid X-Amz-Date format: %w", err)
		}
	} else if date := r.Header.Get(DateHeader); date != "" {
		requestTime, err = time.Parse(time.RFC1123, date)
		if err != nil {
			return fmt.Errorf("invalid Date header format: %w", err)
		}
	} else {
		return fmt.Errorf("missing timestamp header")
	}

	// Check clock skew
	timeDiff := now.Sub(requestTime).Abs()
	if timeDiff > MaxClockSkewSeconds*time.Second {
		return fmt.Errorf("request timestamp too far from current time: %v", timeDiff)
	}

	// Check if request is too old (potential replay attack)
	if now.Sub(requestTime) > MaxClockSkewSeconds*time.Second {
		s.securityMetrics.ReplayAttempts++
		return fmt.Errorf("request timestamp is too old: potential replay attack")
	}

	// Ensure credential date matches request date (within same day)
	credentialDate := credentialTime.Format(ISO8601DateFormat)
	requestDate := requestTime.UTC().Format(ISO8601DateFormat)
	if credentialDate != requestDate {
		return fmt.Errorf("credential date mismatch: %s != %s", credentialDate, requestDate)
	}

	return nil
}

// validateSignature performs AWS Signature V4 validation with security checks
func (s *S3AuthenticationService) validateSignature(r *http.Request, sigInfo *SignatureInfo, secretKey string) error {
	// Get request timestamp for string-to-sign
	var requestTime string
	if amzDate := r.Header.Get(XAmzDateHeader); amzDate != "" {
		requestTime = amzDate
	} else if date := r.Header.Get(DateHeader); date != "" {
		t, err := time.Parse(time.RFC1123, date)
		if err != nil {
			return fmt.Errorf("invalid date format: %w", err)
		}
		requestTime = t.UTC().Format(ISO8601BasicFormat)
	} else {
		return fmt.Errorf("missing timestamp for signature")
	}

	// Build canonical request
	canonicalRequest, err := s.buildCanonicalRequest(r, sigInfo.SignedHeaders)
	if err != nil {
		return fmt.Errorf("failed to build canonical request: %w", err)
	}

	// Build string to sign
	stringToSign := s.buildStringToSign(requestTime, sigInfo.CredentialScope, canonicalRequest)

	// Calculate expected signature
	expectedSignature := s.calculateSignature(secretKey, sigInfo.Date, sigInfo.Region, sigInfo.Service, stringToSign)

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(sigInfo.Signature), []byte(expectedSignature)) != 1 {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// buildCanonicalRequest creates the canonical request for signature verification
func (s *S3AuthenticationService) buildCanonicalRequest(r *http.Request, signedHeaders []string) (string, error) {
	// HTTP Method
	method := r.Method

	// Canonical URI
	uri := r.URL.Path
	if uri == "" {
		uri = "/"
	}
	// URL encode the path but preserve slashes
	uri = strings.ReplaceAll(url.QueryEscape(uri), "%2F", "/")

	// Canonical Query String
	query := s.buildCanonicalQueryString(r.URL.Query())

	// Canonical Headers
	canonicalHeaders, err := s.buildCanonicalHeaders(r, signedHeaders)
	if err != nil {
		return "", fmt.Errorf("failed to build canonical headers: %w", err)
	}

	// Signed Headers
	signedHeadersStr := strings.Join(signedHeaders, ";")

	// Payload Hash
	payloadHash := r.Header.Get(XAmzContentSha256)
	if payloadHash == "" {
		// If not provided, calculate from body or use UNSIGNED-PAYLOAD
		if r.Body != nil && r.ContentLength > 0 {
			// For security, we require explicit payload hash for non-empty bodies
			payloadHash = UnsignedPayload
		} else {
			// Empty payload
			payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // empty SHA256
		}
	}

	// Construct canonical request
	canonicalRequest := method + "\n" +
						uri + "\n" +
						query + "\n" +
						canonicalHeaders + "\n" +
						signedHeadersStr + "\n" +
						payloadHash

	return canonicalRequest, nil
}

// buildCanonicalQueryString creates canonical query string
func (s *S3AuthenticationService) buildCanonicalQueryString(values url.Values) string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var parts []string
	for _, key := range keys {
		for _, value := range values[key] {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}

	return strings.Join(parts, "&")
}

// buildCanonicalHeaders creates canonical headers string
func (s *S3AuthenticationService) buildCanonicalHeaders(r *http.Request, signedHeaders []string) (string, error) {
	headers := make(map[string][]string)

	// Collect all headers (case-insensitive)
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)
		headers[lowerName] = values
	}

	// Add Host header if not present but r.Host is available
	// This is important for HTTP/1.1 clients that don't always include Host in headers
	if _, exists := headers["host"]; !exists && r.Host != "" {
		headers["host"] = []string{r.Host}
	}

	// Build canonical headers for signed headers only
	var canonicalHeaders strings.Builder
	for _, headerName := range signedHeaders {
		lowerName := strings.ToLower(headerName)
		values, exists := headers[lowerName]
		if !exists {
			return "", fmt.Errorf("signed header %s not found in request", headerName)
		}

		// Join multiple values with commas and trim spaces
		var trimmedValues []string
		for _, value := range values {
			trimmedValues = append(trimmedValues, strings.TrimSpace(value))
		}
		headerValue := strings.Join(trimmedValues, ",")

		canonicalHeaders.WriteString(lowerName + ":" + headerValue + "\n")
	}

	return canonicalHeaders.String(), nil
}

// buildStringToSign creates the string to sign for AWS Signature V4
func (s *S3AuthenticationService) buildStringToSign(timestamp, credentialScope, canonicalRequest string) string {
	// Hash the canonical request
	hasher := sha256.New()
	hasher.Write([]byte(canonicalRequest))
	hashedCanonicalRequest := hex.EncodeToString(hasher.Sum(nil))

	return AWS4Algorithm + "\n" +
		   timestamp + "\n" +
		   credentialScope + "\n" +
		   hashedCanonicalRequest
}

// calculateSignature calculates AWS Signature V4
func (s *S3AuthenticationService) calculateSignature(secretKey, date, region, service, stringToSign string) string {
	// Derive signing key
	kDate := s.hmacSHA256([]byte(AWS4Prefix+secretKey), []byte(date))
	kRegion := s.hmacSHA256(kDate, []byte(region))
	kService := s.hmacSHA256(kRegion, []byte(service))
	kSigning := s.hmacSHA256(kService, []byte(AWS4RequestType))

	// Calculate signature
	signature := s.hmacSHA256(kSigning, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

// hmacSHA256 computes HMAC-SHA256
func (s *S3AuthenticationService) hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// logSecurityEvent logs security-related authentication events
func (s *S3AuthenticationService) logSecurityEvent(eventType string, r *http.Request, details string) {
	clientIP := s.getClientIP(r)

	// Track failed attempts per IP
	if strings.Contains(eventType, "failed") || strings.Contains(eventType, "error") {
		s.securityMetrics.FailedAttempts[clientIP]++
	}

	s.logger.WithFields(logrus.Fields{
		"event_type":   eventType,
		"client_ip":    clientIP,
		"user_agent":   r.UserAgent(),
		"method":       r.Method,
		"path":         r.URL.Path,
		"details":      details,
		"failed_count": s.securityMetrics.FailedAttempts[clientIP],
	}).Warn("S3 authentication security event")

	// Alert on repeated failures from same IP
	if s.securityMetrics.FailedAttempts[clientIP] > 5 {
		s.logger.WithFields(logrus.Fields{
			"client_ip":    clientIP,
			"failed_count": s.securityMetrics.FailedAttempts[clientIP],
		}).Error("Potential brute force attack detected")
	}
}

// getClientIP extracts client IP from request
func (s *S3AuthenticationService) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// Take the first IP in the chain
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// GetSecurityMetrics returns current security metrics
func (s *S3AuthenticationService) GetSecurityMetrics() *SecurityMetrics {
	return s.securityMetrics
}

// ResetSecurityMetrics resets security metrics (for maintenance)
func (s *S3AuthenticationService) ResetSecurityMetrics() {
	s.securityMetrics = &SecurityMetrics{
		FailedAttempts: make(map[string]int),
	}
}
