# S3 Encryption Proxy

A Go-based proxy that provides transparent encryption/decryption for S3 objects with multiple encryption providers including Google's Tink, RSA envelope encryption, and direct AES-256-GCM.

## Overview

The S3 Encryption Proxy intercepts S3 API calls and automatically:
- **Encrypts** objects before storing them in S3
- **Decrypts** objects when retrieving them from S3
- **Rotates keys** without re-encrypting data (envelope mode)
- **Maintains** full S3 API compatibility

**Key Features:**
- 🔒 **Transparent Encryption**: No client-side changes required
- 🔑 **Multiple Encryption Providers**: Tink, RSA envelope, and direct AES-256-GCM
- 🚀 **S3 API Compatible**: Works with existing S3 clients and tools
- 🔄 **Key Rotation**: Built-in support without data re-encryption
- 📊 **Production Ready**: Comprehensive testing, monitoring, and CI/CD

## Quick Start

### Docker (Recommended)

Choose your encryption provider:

```bash
# RSA Envelope Encryption (Recommended for production without KMS)
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=rsa-envelope \
  -e RSA_PRIVATE_KEY="$(cat private-key.pem)" \
  -e RSA_PUBLIC_KEY="$(cat public-key.pem)" \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest

# Direct AES Encryption (Simple development setup)
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=aes-gcm \
  -e S3EP_AES_KEY=$(openssl rand -base64 32) \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest

# Tink Envelope with GCP KMS (Enterprise)
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=tink \
  -e TINK_KEK_URI="gcp-kms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key" \
  -v /path/to/gcp-credentials.json:/credentials.json \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest
```

### From Source

```bash
# Clone and build
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
make build

# Generate keys (choose one)
make build-keygen && ./build/s3ep-keygen           # For AES
go build ./cmd/rsa-keygen && ./rsa-keygen 2048     # For RSA

# Run with configuration
./build/s3-encryption-proxy --config config/config-rsa-envelope.yaml
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

## Encryption Providers

The S3 Encryption Proxy supports multiple encryption providers, each optimized for different use cases:

### 🔐 Provider Comparison

| Feature | **Tink Envelope** | **RSA Envelope** | **Direct AES-GCM** | **None** |
|---------|------------------|-------------------|-------------------|----------|
| **Security Level** | 🟢 Very High | 🟢 High | 🟡 Medium | ❌ None |
| **Performance** | 🟡 Good | 🟡 Good | 🟢 Excellent | 🟢 Excellent |
| **KMS Dependency** | ❌ Required | ✅ None | ✅ None | ✅ None |
| **Key Rotation** | 🟢 Automatic | 🔄 Manual | ❌ Not Supported | ❌ N/A |
| **Unique DEK per Object** | ✅ Yes | ✅ Yes | ❌ No | ❌ N/A |
| **Setup Complexity** | 🔴 Complex | 🟡 Medium | 🟢 Simple | 🟢 Simple |
| **Production Ready** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ Testing Only |

### 1. **Tink Envelope Encryption (Recommended for Production)**

**When to use:** Enterprise environments with KMS infrastructure
```yaml
providers:
  - type: "tink"
    config:
      kek_uri: "gcp-kms://projects/.../cryptoKeys/..."
      credentials_path: "/path/to/credentials.json"
```

**Advantages:**
- 🔒 Industry-standard Google Tink cryptography
- 🔄 Automatic key rotation via KMS
- 🛡️ KEK stored securely in external KMS
- 🔑 Unique DEK per object for maximum security

**Disadvantages:**
- 🌐 Requires KMS service dependency
- 💰 Additional KMS costs
- 🔧 More complex setup and configuration

### 2. **RSA Envelope Encryption (Recommended for Self-Hosted)**

**When to use:** Organizations wanting envelope security without KMS dependency
```yaml
providers:
  - type: "rsa-envelope"
    config:
      public_key_pem: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
      private_key_pem: "${RSA_PRIVATE_KEY}"
      key_size: 2048
```

**Advantages:**
- 🔒 Strong envelope encryption (RSA + AES-256-GCM)
- 🏠 Self-contained, no external dependencies
- 🔑 Unique DEK per object
- 💰 No KMS costs
- 🔄 Manual key rotation possible

**Disadvantages:**
- 🔧 Manual key pair management
- 📁 Private key must be securely stored
- 🔄 Key rotation requires manual process

### 3. **Direct AES-256-GCM (Recommended for Development)**

**When to use:** Development, testing, or simple setups
```yaml
providers:
  - type: "aes-gcm"
    config:
      aes_key: "your-base64-encoded-256-bit-key"
```

**Advantages:**
- ⚡ Highest performance (no envelope overhead)
- 🟢 Simple setup and configuration
- 🏠 No external dependencies
- 🔧 Minimal operational complexity

**Disadvantages:**
- 🔑 Single key for all objects
- ❌ No key rotation support
- 🔄 Key compromise affects all data
- 🛡️ Lower security than envelope methods

### 4. **None Provider (Testing Only)**

**When to use:** Development testing, performance benchmarking
```yaml
providers:
  - type: "none"
    config: {}
```

**Advantages:**
- ⚡ Maximum performance (no encryption)
- 🔧 Zero configuration required

**Disadvantages:**
- ❌ No encryption or security
- 🚫 Never use in production

## Multi-Provider Support

The proxy supports multiple providers simultaneously for migration and compatibility:

```yaml
encryption:
  # Active provider for new objects
  encryption_method_alias: "current-rsa"

  # All providers for reading existing objects
  providers:
    - alias: "current-rsa"
      type: "rsa-envelope"
      description: "Current RSA envelope encryption"
      config: { ... }

    - alias: "legacy-aes"
      type: "aes-gcm"
      description: "Legacy AES encryption"
      config: { ... }

    - alias: "future-tink"
      type: "tink"
      description: "Future Tink encryption"
      config: { ... }
```

## Key Generation Tools

### Generate AES Keys
```bash
# Build and run AES key generator
make build-keygen && ./build/s3ep-keygen
```

### Generate RSA Key Pairs
```bash
# Build and run RSA key generator
go build ./cmd/rsa-keygen && ./rsa-keygen 2048
```

## Configuration

### Environment Variables

```bash
# Required (all providers)
export S3EP_TARGET_ENDPOINT="https://s3.amazonaws.com"
export S3EP_REGION="us-east-1"
export S3EP_ACCESS_KEY_ID="your-access-key"
export S3EP_SECRET_KEY="your-secret-key"

# Provider-specific configuration (choose one)

# Tink Envelope (with KMS)
export S3EP_ENCRYPTION_TYPE="tink"
export TINK_KEK_URI="gcp-kms://projects/.../cryptoKeys/..."
export TINK_CREDENTIALS_PATH="/path/to/credentials.json"

# RSA Envelope (no KMS)
export S3EP_ENCRYPTION_TYPE="rsa-envelope"
export RSA_PUBLIC_KEY="$(cat public-key.pem)"
export RSA_PRIVATE_KEY="$(cat private-key.pem)"

# Direct AES (simple)
export S3EP_ENCRYPTION_TYPE="aes-gcm"
export S3EP_AES_KEY="your-base64-encoded-key"
```

### Configuration Examples

#### RSA Envelope Configuration
```yaml
# config-rsa-envelope.yaml
bind_address: "0.0.0.0:8080"
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"

encryption:
  encryption_method_alias: "rsa-envelope"
  providers:
    - alias: "rsa-envelope"
      type: "rsa-envelope"
      description: "RSA envelope encryption with AES-256-GCM"
      config:
        public_key_pem: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
          -----END PUBLIC KEY-----
        private_key_pem: "${RSA_PRIVATE_KEY}"
        key_size: 2048
```

#### Multi-Provider Configuration
```yaml
# config-multi-provider.yaml
encryption:
  encryption_method_alias: "current-rsa"
  providers:
    # Current encryption for new objects
    - alias: "current-rsa"
      type: "rsa-envelope"
      description: "Current RSA envelope encryption"
      config:
        public_key_pem: "${RSA_PUBLIC_KEY}"
        private_key_pem: "${RSA_PRIVATE_KEY}"
        key_size: 2048

    # Legacy encryption for existing objects
    - alias: "legacy-aes"
      type: "aes-gcm"
      description: "Legacy AES-256-GCM encryption"
      config:
        aes_key: "${LEGACY_AES_KEY}"

    # Enterprise encryption for sensitive data
    - alias: "enterprise-tink"
      type: "tink"
      description: "Enterprise Tink encryption with KMS"
      config:
        kek_uri: "${TINK_KEK_URI}"
        credentials_path: "${TINK_CREDENTIALS_PATH}"
```

#### Direct AES Configuration
```yaml
# config-aes.yaml
bind_address: "0.0.0.0:8080"
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"

encryption:
  encryption_method_alias: "aes-simple"
  providers:
    - alias: "aes-simple"
      type: "aes-gcm"
      description: "Direct AES-256-GCM encryption"
      config:
        aes_key: "${AES_ENCRYPTION_KEY}"
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

### Docker

#### RSA Envelope (Recommended)
```bash
# Build
docker build -t s3-encryption-proxy .

# Run with RSA keys
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/keys:/etc/s3ep/keys:ro \
  -e S3EP_TARGET_ENDPOINT="https://s3.amazonaws.com" \
  -e S3EP_REGION="us-east-1" \
  -e S3EP_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e S3EP_SECRET_KEY="$AWS_SECRET_ACCESS_KEY" \
  -e S3EP_ENCRYPTION_TYPE="rsa-envelope" \
  -e RSA_PUBLIC_KEY="$(cat keys/public-key.pem)" \
  -e RSA_PRIVATE_KEY="$(cat keys/private-key.pem)" \
  s3-encryption-proxy
```

#### Tink with KMS
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/gcp-credentials.json:/etc/s3ep/gcp-credentials.json:ro \
  -e S3EP_TARGET_ENDPOINT="https://s3.amazonaws.com" \
  -e S3EP_ENCRYPTION_TYPE="tink" \
  -e TINK_KEK_URI="gcp-kms://projects/my-project/..." \
  -e TINK_CREDENTIALS_PATH="/etc/s3ep/gcp-credentials.json" \
  s3-encryption-proxy
```

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
      - S3EP_ENCRYPTION_TYPE=rsa-envelope
      - RSA_PUBLIC_KEY=${RSA_PUBLIC_KEY}
      - RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY}
    volumes:
      - ./keys:/etc/s3ep/keys:ro
```

### Kubernetes with Helm

```bash
# Use the provided Helm chart
cd deploy/helm
./install.sh production

# Or manually with custom values
helm install s3-encryption-proxy ./s3-encryption-proxy \
  --values values-production.yaml \
  --set encryption.type=rsa-envelope \
  --set-file secrets.rsaKeys.publicKey=keys/public-key.pem \
  --set-file secrets.rsaKeys.privateKey=keys/private-key.pem
```

Example production values:

```yaml
# values-rsa-production.yaml
replicaCount: 3

encryption:
  type: "rsa-envelope"

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

secrets:
  rsaKeys:
    publicKey: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----
    privateKey: "${RSA_PRIVATE_KEY}"
```

See [Deployment Guide](./docs/deployment.md) for complete examples.

## Security

- **🔐 AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **🔑 Envelope Encryption**: KEK/DEK separation with KMS integration
- **🛡️ Security-First Design**: No plaintext keys in storage or logs
- **📋 Compliance Ready**: Supports SOC 2, GDPR, HIPAA requirements

See [Security Guide](./docs/security.md) for detailed security information.

## Performance Testing

The S3 Encryption Proxy includes comprehensive performance tests that compare encrypted proxy performance against direct unencrypted MinIO operations.

### Quick Performance Test

```bash
# Start services (MinIO + Proxy)
docker-compose -f docker-compose.demo.yml up -d

# Run performance comparison
./run-performance-tests.sh comparison
```

### Sample Results

Recent performance benchmarks on Apple M1 Ultra show:

| Metric | Encrypted (via Proxy) | Unencrypted (Direct MinIO) | Efficiency |
|--------|----------------------|---------------------------|------------|
| **Upload Speed** | ~88 MB/s | ~132 MB/s | **66%** |
| **Download Speed** | ~187 MB/s | ~201 MB/s | **93%** |
| **Overall Overhead** | - | - | **~33% slower** |

**Key Findings:**
- ✅ **Download performance** is excellent (~93% of unencrypted speed)
- ⚠️ **Upload performance** shows moderate overhead (~66% of unencrypted speed)
- 📈 **Larger files** perform better due to amortized encryption overhead
- 🔄 **Multipart uploads** (>5MB) show better efficiency ratios

### Available Tests

```bash
# Detailed comparison with multiple file sizes
./run-performance-tests.sh comparison

# Go benchmark tests for CI/CD integration
./run-performance-tests.sh benchmark

# All performance tests
./run-performance-tests.sh all
```

See [Performance Testing Guide](./test/integration/PERFORMANCE.md) for detailed documentation.

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
