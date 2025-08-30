# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of S3 encryption proxy
- Google Tink envelope encryption support
- AES-256-GCM direct encryption support
- Configurable encryption algorithms
- Comprehensive unit and integration tests
- Docker containerization
- CI/CD pipeline with security scanning
- Key generation utility
- Comprehensive documentation

### Security
- All cryptographic operations use industry-standard libraries
- Security scanning with gosec and govulncheck
- No secrets stored in repository
