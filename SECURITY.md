# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it privately by emailing [security@guided-traffic.com](mailto:security@guided-traffic.com).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting a vulnerability, please include:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested mitigation or fix

## Response Timeline

- **Initial Response**: Within 24 hours of receiving the report
- **Confirmation**: Within 48 hours, we'll confirm if the issue is a valid security vulnerability
- **Fix Development**: Depending on complexity, typically within 1-2 weeks
- **Disclosure**: After a fix is available and deployed

## Security Measures

### Encryption

- All data encryption uses Google's Tink cryptographic library
- Envelope encryption with Key Encryption Keys (KEK) and Data Encryption Keys (DEK)
- No plaintext keys are stored or transmitted
- Associated data is used for additional authenticated encryption

### Key Management

- KEKs are managed externally (AWS KMS, GCP KMS, etc.)
- DEKs are generated per object and encrypted with the KEK
- Key rotation is supported without re-encrypting stored data

### Network Security

- TLS is used for all external communications
- No sensitive data is logged
- Configurable security headers

### Infrastructure

- Docker images are built with non-root users
- Minimal attack surface with Alpine Linux base images
- Regular dependency updates

## Best Practices for Users

1. **Key Management**: Use a proper KMS (AWS KMS, GCP KMS, etc.) for KEK storage
2. **Network**: Deploy behind a load balancer with TLS termination
3. **Access Control**: Implement proper IAM policies for S3 access
4. **Monitoring**: Enable logging and monitoring for security events
5. **Updates**: Keep the proxy updated with the latest security patches

## Dependencies

We regularly monitor and update dependencies for security vulnerabilities:

- Go modules are scanned for known vulnerabilities
- Docker base images are updated regularly
- CI/CD pipeline includes security scanning

## Disclosure Policy

- Coordinated disclosure with a 90-day timeline
- Credit will be given to security researchers who responsibly disclose vulnerabilities
- Security advisories will be published for significant vulnerabilities

## Compliance

This project implements cryptographic best practices and follows:

- NIST Cybersecurity Framework guidelines
- OWASP security recommendations
- Industry-standard cryptographic protocols
