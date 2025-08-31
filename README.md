# S3 Encryption Proxy

A Go-based proxy that provides transparent encryption/decryption for S3 objects using Google's Tink cryptographic library with envelope encryption.

## Overview

The S3 Encryption Proxy intercepts S3 API calls and automatically:
- **Encrypts** objects before storing them in S3
- **Decrypts** objects when retrieving them from S3
- **Rotates keys** without re-encrypting data (envelope mode)
- **Maintains** full S3 API compatibility

**Key Features:**
- 🔒 **Transparent Encryption**: No client-side changes required
- 🔑 **Dual Encryption Modes**: Tink envelope encryption or direct AES-256-GCM
- 🚀 **S3 API Compatible**: Works with existing S3 clients and tools
- 🔄 **Key Rotation**: Built-in support without data re-encryption
- 📊 **Production Ready**: Comprehensive testing, monitoring, and CI/CD

## Quick Start

### Docker (Recommended)

```bash
# Using direct AES encryption (simple setup)
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=aes256-gcm \
  -e S3EP_AES_KEY=$(openssl rand -base64 32) \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest
```

### From Source

```bash
# Clone and build
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
make build

# Generate AES key
make build-keygen && ./build/s3ep-keygen

# Run with configuration
./build/s3-encryption-proxy --config config/config.yaml
```

### Client Usage

Use any S3 client with the proxy endpoint:

```bash
# AWS CLI
aws s3 --endpoint-url http://localhost:8080 cp file.txt s3://my-bucket/

# Python boto3
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:8080')
s3.put_object(Bucket='my-bucket', Key='file.txt', Body=b'data')
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   S3 Client     │───►│ Encryption      │───►│   S3 Storage    │
│   (boto3, aws   │    │ Proxy           │    │   (AWS/MinIO)   │
│   cli, etc.)    │◄───│ (Go Service)    │◄───│                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                      ┌─────────────┐
                      │     KMS     │
                      │ (Optional)  │
                      └─────────────┘
```

**Envelope Encryption (Default):**
- KEK (Key Encryption Key) stored in KMS
- DEK (Data Encryption Key) unique per object
- Encrypted DEK stored in S3 metadata

**Direct AES-256-GCM:**
- Single master key for all operations
- Faster, no KMS dependency
- Suitable for development/simple setups

## Configuration

### Environment Variables

```bash
# Required
export S3EP_TARGET_ENDPOINT="https://s3.amazonaws.com"
export S3EP_REGION="us-east-1"
export S3EP_ACCESS_KEY_ID="your-access-key"
export S3EP_SECRET_KEY="your-secret-key"

# Encryption (choose one)
export S3EP_ENCRYPTION_TYPE="tink"  # or "aes256-gcm"
export S3EP_KEK_URI="gcp-kms://projects/.../cryptoKeys/..."  # Tink mode
export S3EP_AES_KEY="your-base64-encoded-key"  # AES mode
```

### Configuration File

```yaml
# config.yaml
bind_address: "0.0.0.0:8080"
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"
encryption_type: "tink"  # or "aes256-gcm"
kek_uri: "gcp-kms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
```

## Documentation

Comprehensive documentation is available in the [`docs/`](./docs/) directory:

### 📖 User Guides
- **[Configuration Guide](./docs/configuration.md)** - Complete configuration reference with examples
- **[Deployment Guide](./docs/deployment.md)** - Docker, Kubernetes, cloud deployment options
- **[API Reference](./docs/api-reference.md)** - S3 API compatibility and client integration

### 🏗️ Architecture & Development
- **[Architecture Guide](./docs/architecture.md)** - System design and encryption flows
- **[Development Guide](./docs/development.md)** - Developer setup and contribution guidelines
- **[Security Guide](./docs/security.md)** - Security architecture and best practices

### 📋 Reference
- **[Project Summary](./PROJECT-SUMMARY.md)** - High-level project overview
- **[Contributing Guidelines](./CONTRIBUTING.md)** - How to contribute
- **[Security Policy](./SECURITY.md)** - Security reporting procedures

## Deployment Options

### Docker Compose

```yaml
version: '3.8'
services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com
      - S3EP_ENCRYPTION_TYPE=aes256-gcm
      - S3EP_AES_KEY=${AES_KEY}
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-encryption-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: s3-encryption-proxy
  template:
    spec:
      containers:
      - name: s3-encryption-proxy
        image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
        ports:
        - containerPort: 8080
```

See [Deployment Guide](./docs/deployment.md) for complete examples.

## Security

- **🔐 AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **🔑 Envelope Encryption**: KEK/DEK separation with KMS integration
- **🛡️ Security-First Design**: No plaintext keys in storage or logs
- **📋 Compliance Ready**: Supports SOC 2, GDPR, HIPAA requirements

See [Security Guide](./docs/security.md) for detailed security information.

## Development

```bash
# Setup development environment
make deps && make tools

# Run tests
make test

# Code quality checks
make quality

# Local development server
make dev
```

See [Development Guide](./docs/development.md) for complete developer information.

## License

See [LICENSE](./LICENSE) file for details.
