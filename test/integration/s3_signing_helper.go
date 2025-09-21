//go:build integration

package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSV4Signer handles AWS Signature Version 4 signing for HTTP requests
type AWSV4Signer struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

// NewAWSV4Signer creates a new AWS Signature V4 signer with the given credentials
func NewAWSV4Signer(accessKey, secretKey, region, service string) *AWSV4Signer {
	return &AWSV4Signer{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
		Service:   service,
	}
}

// SignRequest signs an HTTP request using AWS Signature Version 4
func (s *AWSV4Signer) SignRequest(req *http.Request, payloadHash string, timestamp time.Time) error {
	// Step 1: Create canonical request
	canonicalRequest := s.createCanonicalRequest(req, payloadHash)

	// Step 2: Create string to sign
	stringToSign := s.createStringToSign(canonicalRequest, timestamp)

	// Step 3: Calculate signature
	signature := s.calculateSignature(stringToSign, timestamp)

	// Step 4: Add authorization header
	s.addAuthorizationHeader(req, signature, timestamp)

	return nil
}

// createCanonicalRequest creates the canonical request string according to AWS Signature V4
func (s *AWSV4Signer) createCanonicalRequest(req *http.Request, payloadHash string) string {
	// HTTP Method
	httpMethod := req.Method

	// Canonical URI
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical Query String
	canonicalQueryString := s.createCanonicalQueryString(req.URL.Query())

	// Canonical Headers
	canonicalHeaders, signedHeaders := s.createCanonicalHeaders(req.Header)

	// Create canonical request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash)

	return canonicalRequest
}

// createCanonicalQueryString creates canonical query string from URL parameters
func (s *AWSV4Signer) createCanonicalQueryString(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	var params []string
	for key, vals := range values {
		for _, val := range vals {
			params = append(params, fmt.Sprintf("%s=%s",
				url.QueryEscape(key), url.QueryEscape(val)))
		}
	}

	sort.Strings(params)
	return strings.Join(params, "&")
}

// createCanonicalHeaders creates canonical headers and signed headers list
func (s *AWSV4Signer) createCanonicalHeaders(headers http.Header) (string, string) {
	var headerKeys []string
	headerMap := make(map[string]string)

	// List of hop-by-hop headers that should not be included in AWS Signature V4
	hopByHopHeaders := map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailers":            true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}

	// Normalize header names and collect unique keys (excluding hop-by-hop headers)
	for name, values := range headers {
		lowerName := strings.ToLower(name)

		// Skip hop-by-hop headers for AWS Signature V4
		if hopByHopHeaders[lowerName] {
			continue
		}

		headerKeys = append(headerKeys, lowerName)
		headerMap[lowerName] = strings.Join(values, ",")
	}

	// Sort header keys
	sort.Strings(headerKeys)

	// Build canonical headers
	var canonicalHeaders []string
	for _, key := range headerKeys {
		canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", key, headerMap[key]))
	}

	// Create signed headers list
	signedHeaders := strings.Join(headerKeys, ";")

	return strings.Join(canonicalHeaders, "\n") + "\n", signedHeaders
}

// createStringToSign creates the string to sign according to AWS Signature V4
func (s *AWSV4Signer) createStringToSign(canonicalRequest string, timestamp time.Time) string {
	algorithm := "AWS4-HMAC-SHA256"
	requestDateTime := timestamp.UTC().Format("20060102T150405Z")
	credentialScope := s.createCredentialScope(timestamp)
	hashedCanonicalRequest := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))

	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		requestDateTime,
		credentialScope,
		hashedCanonicalRequest)

	return stringToSign
}

// createCredentialScope creates credential scope for the request
func (s *AWSV4Signer) createCredentialScope(timestamp time.Time) string {
	dateStamp := timestamp.UTC().Format("20060102")
	return fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, s.Region, s.Service)
}

// calculateSignature calculates the AWS Signature V4 signature
func (s *AWSV4Signer) calculateSignature(stringToSign string, timestamp time.Time) string {
	dateStamp := timestamp.UTC().Format("20060102")

	// Create signing key
	dateKey := s.hmacSHA256([]byte("AWS4"+s.SecretKey), dateStamp)
	regionKey := s.hmacSHA256(dateKey, s.Region)
	serviceKey := s.hmacSHA256(regionKey, s.Service)
	signingKey := s.hmacSHA256(serviceKey, "aws4_request")

	// Calculate signature
	signature := s.hmacSHA256(signingKey, stringToSign)
	return fmt.Sprintf("%x", signature)
}

// hmacSHA256 calculates HMAC-SHA256 hash
func (s *AWSV4Signer) hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// addAuthorizationHeader adds the Authorization header to the request
func (s *AWSV4Signer) addAuthorizationHeader(req *http.Request, signature string, timestamp time.Time) {
	credentialScope := s.createCredentialScope(timestamp)

	// Get signed headers from the canonical headers
	var headerKeys []string
	for name := range req.Header {
		headerKeys = append(headerKeys, strings.ToLower(name))
	}
	sort.Strings(headerKeys)
	signedHeaders := strings.Join(headerKeys, ";")

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKey,
		credentialScope,
		signedHeaders,
		signature)

	req.Header.Set("Authorization", authHeader)
}

// SignHTTPRequest signs an HTTP request for S3 with AWS Signature V4
// This is a convenience function that sets required headers and signs the request
func SignHTTPRequestForS3(req *http.Request, accessKey, secretKey, region string, payloadHash string) error {
	// Set required AWS headers if not already set
	timestamp := time.Now().UTC()

	if req.Header.Get("X-Amz-Date") == "" {
		req.Header.Set("X-Amz-Date", timestamp.Format("20060102T150405Z"))
	}

	if req.Header.Get("X-Amz-Content-Sha256") == "" && payloadHash != "" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// Create signer and sign request
	signer := NewAWSV4Signer(accessKey, secretKey, region, "s3")
	return signer.SignRequest(req, payloadHash, timestamp)
}

// SignHTTPRequestForS3WithCredentials signs an HTTP request using the default proxy test credentials
func SignHTTPRequestForS3WithCredentials(req *http.Request, payloadHash string) error {
	return SignHTTPRequestForS3(req, ProxyTestAccessKey, ProxyTestSecretKey, TestRegion, payloadHash)
}
