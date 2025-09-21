# Security Guide

## Overview

This document outlines the security architecture, best practices, and considerations for the S3 Encryption Proxy. The proxy is designed with security-first principles to protect data at rest, in transit, and during processing.

## Security Architecture

### Threat Model

**Assets Protected:**
- S3 object data (files, documents, media)
- Encryption keys (KEKs and DEKs)
- Application credentials and configuration
- Metadata about encrypted objects

**Threat Actors:**
- Unauthorized external access
- Compromised S3 bucket access
- Insider threats with S3 access
- Network-based attacks
- Application vulnerabilities

**Attack Vectors:**
- Direct S3 bucket access
- Man-in-the-middle attacks
- Key compromise
- Application-level vulnerabilities
- Infrastructure compromise

### Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Boundaries                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐     │
│  │   Client    │───►│ S3 Encryption   │───►│     S3      │     │
│  │             │    │     Proxy       │    │   Storage   │     │
│  │ (Trusted)   │    │  (Trusted)      │    │ (Untrusted) │     │
│  └─────────────┘    └─────────────────┘    └─────────────┘     │
│                              │                                  │
│                              ▼                                  │
│                      ┌─────────────┐                           │
│                      │     KMS     │                           │
│                      │ (Trusted)   │                           │
│                      └─────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Trusted Zone:** Client, Proxy, KMS
**Untrusted Zone:** S3 Storage

## Encryption Security

### Envelope Encryption (Recommended)

**Security Properties:**
- **Key Separation**: KEK stored in KMS, DEK encrypted at rest
- **Perfect Forward Secrecy**: Unique DEK per object
- **Key Rotation**: KEK rotation without data re-encryption
- **Associated Data**: Object key binding prevents tampering

**Implementation Details:**
```
Data Encryption:
├── DEK Generation: 256-bit random key per object
├── Data Encryption: aes-gcm with DEK
├── DEK Encryption: KEK encrypts DEK via Tink/KMS
├── Metadata Storage: Encrypted DEK + algorithm info
└── Associated Data: S3 object key for integrity binding
```

**Key Management Flow:**
```
1. Generate random 256-bit DEK
2. Encrypt object data with DEK (aes-gcm)
3. Encrypt DEK with KEK via KMS
4. Store encrypted DEK in S3 object metadata
5. Store encrypted data as S3 object content
```

### Direct aes-gcm Encryption

**Security Properties:**
- **Authenticated Encryption**: Built-in integrity protection
- **Unique Nonces**: 96-bit random nonce per operation
- **Associated Data**: Object key binding
- **Performance**: Lower latency than envelope encryption

**Implementation Details:**
```
Data Encryption:
├── Master Key: 256-bit AES key (static)
├── Nonce Generation: 96-bit random per operation
├── Data Encryption: aes-gcm with master key
├── Metadata Storage: Nonce + algorithm info
└── Associated Data: S3 object key for integrity binding
```

### Cryptographic Standards

**Algorithms:**
- **Symmetric Encryption**: aes-gcm
- **Key Derivation**: PBKDF2 (where applicable)
- **Random Generation**: Cryptographically secure (crypto/rand)
- **Authentication**: GCM mode provides AEAD

**Key Sizes:**
- **KEK**: Managed by KMS (typically 256-bit AES)
- **DEK**: 256-bit AES
- **Direct Mode**: 256-bit AES
- **Nonces**: 96-bit (AES-GCM standard)

## Key Management Security

### Key Encryption Key (KEK) Management

**Best Practices:**
```yaml
# Google Cloud KMS Example
kek_uri: "gcp-kms://projects/prod-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"

# Key Properties:
# - Automatic rotation support
# - Hardware Security Module (HSM) backed
# - Audit logging enabled
# - Cross-region replication
# - IAM-based access control
```

**KMS Security Configuration:**
```json
{
  "keyManagement": {
    "rotation": {
      "enabled": true,
      "period": "90d"
    },
    "access": {
      "serviceAccount": "s3-encryption-proxy@project.iam.gserviceaccount.com",
      "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt", "cloudkms.cryptoKeyVersions.useToDecrypt"]
    },
    "audit": {
      "enabled": true,
      "destination": "cloud-logging"
    }
  }
}
```

### Data Encryption Key (DEK) Security

**DEK Lifecycle:**
1. **Generation**: Cryptographically secure random
2. **Usage**: Single object encryption/decryption
3. **Storage**: Encrypted with KEK in S3 metadata
4. **Memory**: Cleared after use (automatic GC)
5. **Rotation**: Automatic with key rotation

**DEK Storage Format:**
```json
{
  "x-s3ep-encrypted-key": "base64-encoded-encrypted-dek",
  "x-s3ep-algorithm": "AES256_GCM",
  "x-s3ep-key-version": "1",
  "x-s3ep-nonce": "base64-encoded-nonce"
}
```

## Network Security

### TLS Configuration

**Minimum Requirements:**
- TLS 1.2 minimum (TLS 1.3 preferred)
- Strong cipher suites only
- Perfect Forward Secrecy
- Certificate validation

**Example NGINX Configuration:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_dhparam /etc/ssl/dhparam.pem;
```

### Certificate Management

**Best Practices:**
- Use certificates from trusted CAs
- Implement certificate rotation
- Monitor certificate expiry
- Use certificate pinning where possible

**Let's Encrypt Example:**
```bash
# Automated certificate management
certbot --nginx -d s3-proxy.yourdomain.com
```

## Application Security

### Input Validation

**S3 Request Validation:**
- Object key validation (path traversal prevention)
- Request size limits
- Content-type validation
- Header sanitization

**Example Validation:**
```go
func validateObjectKey(key string) error {
    if strings.Contains(key, "..") {
        return errors.New("invalid object key: path traversal attempt")
    }
    if len(key) > 1024 {
        return errors.New("object key too long")
    }
    return nil
}
```

### Authentication and Authorization

**S3 API Compatibility:**
- AWS Signature Version 4 support
- IAM-based access control
- Bucket policy enforcement
- Access logging

**Proxy Authentication:**
- Pass-through S3 authentication
- No additional authentication layer
- Credential validation at S3 backend

### Error Handling

**Security Considerations:**
- No sensitive information in error messages
- Consistent error responses
- Rate limiting on authentication failures
- Audit logging of security events

**Example Secure Error Handling:**
```go
func handleEncryptionError(err error) *APIError {
    // Log detailed error internally
    log.WithError(err).Error("encryption operation failed")

    // Return generic error to client
    return &APIError{
        Code:    "InternalError",
        Message: "An internal error occurred",
    }
}
```

## Infrastructure Security

### Container Security

**Docker Security:**
```dockerfile
# Use minimal base image
FROM alpine:3.18

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set security options
USER appuser
WORKDIR /app

# Read-only filesystem
RUN chmod -R 755 /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
```

**Kubernetes Security Context:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

### Network Policies

**Kubernetes Network Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: s3-encryption-proxy-netpol
spec:
  podSelector:
    matchLabels:
      app: s3-encryption-proxy
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []  # S3 and KMS endpoints
    ports:
    - protocol: TCP
      port: 443
  - to: []  # DNS
    ports:
    - protocol: UDP
      port: 53
```

## Monitoring and Auditing

### Security Monitoring

**Metrics to Monitor:**
- Authentication failures
- Encryption/decryption errors
- Unusual access patterns
- KMS operation failures
- Network connection errors

**Example Prometheus Alerts:**
```yaml
groups:
- name: s3-encryption-proxy-security
  rules:
  - alert: HighAuthenticationFailures
    expr: rate(s3_auth_failures_total[5m]) > 10
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate"

  - alert: EncryptionFailures
    expr: rate(s3_encryption_errors_total[5m]) > 1
    for: 30s
    labels:
      severity: critical
    annotations:
      summary: "Encryption operations failing"
```

### Audit Logging

**Security Events to Log:**
- All encryption/decryption operations
- Key access and rotation events
- Authentication attempts
- Configuration changes
- Error conditions

**Log Format Example:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "event": "object_encrypted",
  "object_key": "documents/file.pdf",
  "bucket": "my-secure-bucket",
  "encryption_type": "tink",
  "kek_version": "1",
  "user_id": "user123",
  "source_ip": "10.0.1.50",
  "user_agent": "aws-cli/2.1.0"
}
```

## Compliance and Standards

### Compliance Frameworks

**Supported Standards:**
- **SOC 2 Type II**: Security, availability, processing integrity
- **ISO 27001**: Information security management
- **GDPR**: Data protection and privacy
- **HIPAA**: Healthcare data protection (with proper implementation)
- **PCI DSS**: Payment card industry standards

### Cryptographic Compliance

**FIPS 140-2:**
- Use FIPS-validated cryptographic modules where required
- Configure Tink with FIPS-compliant algorithms
- Ensure KMS providers are FIPS-validated

**Common Criteria:**
- Use Common Criteria certified KMS where required
- Document security configurations
- Implement proper key management procedures

## Security Best Practices

### Deployment Security

**Production Checklist:**
- [ ] TLS 1.2+ for all communications
- [ ] Valid certificates from trusted CA
- [ ] KEK stored in hardware-backed KMS
- [ ] Unique keys per environment
- [ ] Network segmentation implemented
- [ ] Security monitoring enabled
- [ ] Audit logging configured
- [ ] Regular security updates
- [ ] Vulnerability scanning enabled
- [ ] Incident response plan in place

### Operational Security

**Key Rotation:**
```bash
# Automated key rotation (Google Cloud)
gcloud kms keys update master-key \
  --location=global \
  --keyring=s3-encryption \
  --next-rotation-time=2024-04-15T00:00:00Z \
  --rotation-period=90d
```

**Backup and Recovery:**
- Regular backup of configuration
- Test disaster recovery procedures
- Document key recovery processes
- Implement geo-redundant storage

**Access Control:**
- Principle of least privilege
- Regular access reviews
- Strong authentication (MFA)
- Separation of duties

### Development Security

**Secure Development:**
- Security code reviews
- Static application security testing (SAST)
- Dynamic application security testing (DAST)
- Dependency vulnerability scanning
- Security unit tests

**Example Security Test:**
```go
func TestEncryptionKeyIsolation(t *testing.T) {
    // Ensure different objects use different DEKs
    key1, _ := generateDEK()
    key2, _ := generateDEK()

    assert.NotEqual(t, key1, key2, "DEKs should be unique")
}
```

## Incident Response

### Security Incident Types

**Critical Incidents:**
- Suspected key compromise
- Data breach or unauthorized access
- Encryption failures
- Authentication bypass

**Response Procedures:**
1. **Immediate**: Isolate affected systems
2. **Short-term**: Rotate compromised keys
3. **Medium-term**: Investigate root cause
4. **Long-term**: Implement preventive measures

### Key Compromise Response

**KEK Compromise:**
```bash
# 1. Immediately disable old KEK
gcloud kms keys update master-key --primary-version=NEW_VERSION

# 2. Generate new KEK version
gcloud kms keys create-version master-key

# 3. Re-encrypt all DEKs (automated by service)
# 4. Monitor for unauthorized access
# 5. Audit all recent operations
```

**Recovery Procedures:**
- Document all actions taken
- Preserve forensic evidence
- Notify relevant stakeholders
- Update security procedures

For incident response procedures, see [Incident Response Playbook](./incident-response.md).

## Security Assessment

### Penetration Testing

**Test Scenarios:**
- Network-based attacks
- Application vulnerabilities
- Key management weaknesses
- Authentication bypass attempts
- Data exfiltration attempts

### Security Reviews

**Regular Assessments:**
- Quarterly security reviews
- Annual penetration testing
- Continuous vulnerability scanning
- Code security audits
- Configuration reviews

**Security Metrics:**
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Vulnerability remediation time
- Security training completion
- Compliance audit results

For additional security information, see:
- [Incident Response Guide](./incident-response.md)
- [Compliance Documentation](./compliance.md)
- [Security Architecture Diagrams](./diagrams/)
