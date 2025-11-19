# S3 Encryption Proxy

A Go-based proxy that provides transparent encryption/decryption for S3 objects with envelope encryption (RSA or AES), streaming multipart uploads, and HMAC integrity verification.


## Overview

The S3 Encryption Proxy intercepts S3 API calls and automatically:
- **Encrypts** objects before storing them in S3 using envelope encryption (unique DEK per object)
- **Decrypts** objects when retrieving them from S3 with automatic provider detection
- **Verifies** data integrity using HMAC-SHA256 with configurable modes
- **Maintains** full S3 API compatibility with streaming support for large files

**Key Features:**
- 🔒 **Transparent Encryption**: No client-side changes required
- 🔑 **Envelope Encryption**: RSA or AES KEK with unique AES DEK per object
- 🚀 **S3 API Compatible**: Works with existing S3 clients and tools
- � **Streaming Uploads**: Memory-efficient multipart uploads with configurable buffer sizes
- 🛡️ **Integrity Verification**: HMAC-SHA256 with off/lax/strict/hybrid modes
- 🔐 **Client Authentication**: AWS Signature V4 validation with rate limiting
- � **Production Ready**: Comprehensive testing, monitoring, and CI/CD

## Quick Start

### Local Demo (Fastest)

```bash
# Start MinIO + S3 Encryption Proxy + S3 Explorers
./start-demo.sh

# Access S3 Explorer (view encrypted data): http://localhost:9001
# Access Direct S3 Explorer (view raw data): http://localhost:9002
# Proxy endpoint: http://localhost:8080
# Metrics endpoint: http://localhost:9090/metrics
```

### Docker (Recommended)

Choose your encryption provider:

```bash
# RSA Envelope Encryption (Recommended for production)
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/config:/config:ro \
  -e RSA_PRIVATE_KEY="$(cat private-key.pem)" \
  -e RSA_PUBLIC_KEY="$(cat public-key.pem)" \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest \
  --config /config/rsa-example.yaml

# AES Envelope Encryption (Simple development setup)
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/config:/config:ro \
  -e AES_KEY=$(openssl rand -base64 32) \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest \
  --config /config/aes-example.yaml
```

### From Source

```bash
# Clone and build
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
make build

# Generate keys (choose one)
make build-keygen && ./build/s3ep-keygen           # For AES (outputs base64 key)
go build ./cmd/rsa-keygen && ./rsa-keygen 2048     # For RSA (generates PEM files)

# Update config file with generated keys
# Edit config/aes-example.yaml or config/rsa-example.yaml

# Run with configuration
./build/s3-encryption-proxy --config config/aes-example.yaml
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

| Feature | **RSA Envelope** | **AES Envelope** | **None** |
|---------|------------------|------------------|----------|
| **Security Level** | 🟢 High | 🟢 High | ❌ None |
| **Performance** | 🟡 Good | 🟢 Excellent | 🟢 Excellent |
| **KMS Dependency** | ✅ None | ✅ None | ✅ None |
| **Key Rotation** | � Manual | 🔄 Manual | ❌ N/A |
| **Unique DEK per Object** | ✅ Yes | ✅ Yes | ❌ N/A |
| **Setup Complexity** | 🟡 Medium | 🟢 Simple | 🟢 Simple |
| **Production Ready** | ✅ Yes | ✅ Yes | ❌ Testing Only |

### 1. **RSA Envelope Encryption (Recommended for Production)**

**When to use:** Organizations wanting envelope security without KMS dependency
```yaml
providers:
  - alias: "rsa-envelope"
    type: "rsa"
    description: "RSA envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
    config:
      public_key_pem: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
      private_key_pem: "${RSA_PRIVATE_KEY}"
```

**Advantages:**
- 🔒 Strong envelope encryption (RSA + AES-GCM/AES-CTR)
- 🏠 Self-contained, no external dependencies
- 🔑 Unique DEK per object
- 💰 No KMS costs
- 🔄 Manual key rotation possible

**Disadvantages:**
- 🔧 Manual key pair management
- 📁 Private key must be securely stored
- 🔄 Key rotation requires manual process

### 2. **AES Envelope Encryption (Recommended for Development)**

**When to use:** Development, testing, or simple production setups
```yaml
providers:
  - alias: "aes-envelope"
    type: "aes"
    description: "AES envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
    config:
      aes_key: "base64-encoded-256-bit-key"
```

**Advantages:**
- ⚡ High performance with envelope security
- 🟢 Simple setup and configuration
- 🏠 No external dependencies
- 🔑 Unique DEK per object
- 🔧 Minimal operational complexity

**Disadvantages:**
- 🔑 Single master key for all DEK encryption
- 🔄 Key compromise affects all data
- 🛡️ Lower security than RSA (symmetric key distribution)

### 3. **None Provider (Testing Only)**

**When to use:** Development testing, performance benchmarking
```yaml
providers:
  - alias: "default"
    type: "none"
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
  encryption_method_alias: "aes-current"

  # Integrity verification: off, lax, strict, hybrid
  integrity_verification: "strict"

  # All providers for reading existing objects
  providers:
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

    - alias: "rsa-backup"
      type: "rsa"
      description: "Backup RSA envelope encryption"
      config:
        public_key_pem: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----
        private_key_pem: |
          -----BEGIN PRIVATE KEY-----
          ...
          -----END PRIVATE KEY-----
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

### Complete Configuration File Structure

```yaml
# Server Configuration
bind_address: "0.0.0.0:8080"
log_level: "debug"  # debug, info, warn, error
log_format: "text"  # text or json
log_health_requests: false

# S3 Backend Configuration
s3_backend:
  target_endpoint: "https://s3.amazonaws.com"
  region: "us-east-1"
  access_key_id: "your-access-key"
  secret_key: "your-secret-key"
  use_tls: true
  insecure_skip_verify: false

# S3 Client Authentication (Enterprise Security)
s3_clients:
  - type: "static"
    access_key_id: "client-user"
    secret_key: "minimum-16-chars"  # minimum 16 characters
    description: "Client authentication"

# S3 Security Configuration
s3_security:
  strict_signature_validation: true
  max_clock_skew_seconds: 300  # 5 minutes
  enable_rate_limiting: true
  max_requests_per_minute: 60
  enable_security_logging: true
  max_failed_attempts: 5
  unblock_ip_seconds: 60

# Monitoring
monitoring:
  enabled: true
  bind_address: ":9090"
  metrics_path: "/metrics"

# License
license_file: "config/license.jwt"

# Encryption Configuration
encryption:
  encryption_method_alias: "current-provider"
  integrity_verification: "strict"  # off, lax, strict, hybrid
  # metadata_key_prefix: "s3ep-"    # Optional custom prefix
  providers:
    - alias: "current-provider"
      type: "aes"  # or "rsa", "none"
      config: { ... }

# Performance Optimizations
optimizations:
  streaming_buffer_size: 65536      # 64KB (4KB - 2MB)
  streaming_segment_size: 12582912  # 12MB (5MB - 5GB)
  enable_adaptive_buffering: false
  streaming_threshold: 5242880      # 5MB
  clean_aws_signature_v4_chunked: true
  clean_http_transfer_chunked: false
```

### Environment Variables

Environment variables can be used in configuration files with `${VAR_NAME}` syntax:

```bash
# S3 Backend
export S3_TARGET_ENDPOINT="https://s3.amazonaws.com"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY="your-access-key"
export S3_SECRET_KEY="your-secret-key"

# Provider-specific (choose one)

# RSA Envelope
export RSA_PUBLIC_KEY="$(cat public-key.pem)"
export RSA_PRIVATE_KEY="$(cat private-key.pem)"

# AES Envelope
export AES_KEY="$(./build/s3ep-keygen)"
```

### Configuration Examples

See complete examples in the `config/` directory:

#### RSA Envelope Configuration (`config/rsa-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "rsa-envelope"
  integrity_verification: "strict"
  providers:
    - alias: "rsa-envelope"
      type: "rsa"
      description: "RSA envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
      config:
        public_key_pem: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
          -----END PUBLIC KEY-----
        private_key_pem: "${RSA_PRIVATE_KEY}"
```

#### AES Envelope Configuration (`config/aes-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-envelope"
  integrity_verification: "strict"
  providers:
    - alias: "aes-envelope"
      type: "aes"
      description: "AES envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="
```

#### Multi-Provider Configuration (`config/multi-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-current"
  integrity_verification: "strict"
  providers:
    # Current encryption for new objects
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

    # Backup encryption for migration
    - alias: "rsa-backup"
      type: "rsa"
      description: "Backup RSA envelope encryption"
      config:
        public_key_pem: "${RSA_PUBLIC_KEY}"
        private_key_pem: "${RSA_PRIVATE_KEY}"
```

#### None Provider Configuration (`config/none-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "default"
  integrity_verification: "lax"
  providers:
    - alias: "default"
      type: "none"
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

#### With Configuration File (Recommended)
```bash
# Build
docker build -t s3-encryption-proxy .

# Run with config file
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

#### With Environment Variables
```bash
# RSA Envelope
docker run -d \
  -p 8080:8080 \
  -e RSA_PUBLIC_KEY="$(cat keys/public-key.pem)" \
  -e RSA_PRIVATE_KEY="$(cat keys/private-key.pem)" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/rsa-example.yaml

# AES Envelope
docker run -d \
  -p 8080:8080 \
  -e AES_KEY="$(./build/s3ep-keygen)" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

### Docker Compose

```yaml
version: '3.8'
services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics
    environment:
      - RSA_PUBLIC_KEY=${RSA_PUBLIC_KEY}
      - RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY}
    volumes:
      - ./config:/config:ro
    command: ["--config", "/config/rsa-example.yaml"]
```

### Kubernetes with Helm

```bash
# Use the provided Helm chart
cd deploy/helm
./install.sh production

# Or manually with custom values
helm install s3-encryption-proxy ./s3-encryption-proxy \
  --values values-production.yaml \
  --set-file config.yaml=config/rsa-example.yaml \
  --set-file secrets.rsaPrivateKey=keys/private-key.pem
```

Example production values:

```yaml
# values-production.yaml
replicaCount: 3

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

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

See [Deployment Guide](./docs/deployment.md) for complete examples.

## Security

- **🔐 AES-GCM/AES-CTR Encryption**: Industry-standard authenticated encryption
- **🔑 Envelope Encryption**: KEK/DEK separation for maximum security
- **🛡️ Integrity Verification**: HMAC-SHA256 with configurable modes (off, lax, strict, hybrid)
- **🔒 Client Authentication**: AWS Signature V4 validation with rate limiting
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
