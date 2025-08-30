# S3 Encryption Proxy

A Go-based proxy that provides transparent encryption/decryption for S3 objects using Google's Tink cryptographic library with envelope encryption.

## Overview

The S3 Encryption Proxy intercepts S3 API calls and:
- Encrypts objects before storing them in S3 using envelope encryption
- Decrypts objects when retrieving them from S3
- Uses Google's Tink library for cryptographic operations
- Supports configurable encryption algorithms
- Provides key rotation capabilities without re-encrypting data

## Architecture

The proxy uses envelope encryption with:
- **Key Encryption Key (KEK)**: Master key used to encrypt data encryption keys
- **Data Encryption Key (DEK)**: Unique key for each S3 object
- **Metadata Storage**: Encrypted DEK stored as S3 object metadata

## Features

- Transparent S3 API compatibility
- Envelope encryption for scalable key management
- Pluggable encryption algorithms via Tink
- Key rotation support
- Comprehensive logging and monitoring
- Unit and integration tests

## Getting Started

### Prerequisites

- Go 1.23+
- AWS credentials configured
- Access to an S3 bucket

### Building

```bash
make build
```

### Running

```bash
make run
```

### Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Generate coverage report
make coverage
```

## Configuration

The proxy supports two encryption methods:

### 1. Google Tink (Envelope Encryption) - Default
Uses Google's Tink cryptographic library with envelope encryption pattern:
- KEK (Key Encryption Key) stored in KMS (Google Cloud KMS, AWS KMS, etc.)
- DEK (Data Encryption Key) generated per operation and encrypted with KEK
- Provides key rotation capabilities

### 2. Direct AES-256-GCM
Uses direct AES-256-GCM encryption:
- Single key for all operations
- Simpler setup but no built-in key rotation
- Suitable for scenarios where KMS is not available

### Configuration Examples

**Tink (Envelope Encryption):**
```yaml
encryption_type: "tink"
kek_uri: "gcp-kms://projects/your-project/locations/global/keyRings/your-ring/cryptoKeys/your-key"
credentials_path: "/path/to/service-account.json"
```

**AES-256-GCM (Direct Encryption):**
```yaml
encryption_type: "aes256-gcm"
aes_key: "your-base64-encoded-256-bit-key"
```

Generate an AES key using the provided tool:
```bash
make build-keygen
./build/s3ep-keygen
```

### Configuration Sources
Configuration can be provided via:
- Environment variables (prefix: `S3EP_`)
- Configuration file (YAML/JSON)
- Command line flags

See `config/` directory for examples.

## License

See LICENSE file for details.
