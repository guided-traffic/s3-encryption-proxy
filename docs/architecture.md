# Architecture Documentation

## System Overview

The S3 Encryption Proxy acts as a transparent middleware between S3 clients and S3 storage, providing automatic encryption and decryption of objects.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   S3 Client     │───►│ Encryption      │───►│   S3 Storage    │
│   (boto3, aws   │    │ Proxy           │    │   (AWS/MinIO)   │
│   cli, etc.)    │◄───│ (Go Service)    │◄───│                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Component Architecture

### Core Components

```
s3-encryption-proxy/
├── cmd/
│   ├── s3-encryption-proxy/   # Main application entry point
│   └── keygen/                # AES key generation utility
├── internal/                   # Private application code
│   ├── config/                # Configuration management
│   ├── encryption/            # Encryption manager
│   ├── proxy/                 # HTTP proxy server
│   └── s3/                    # S3 client wrapper
├── pkg/
│   ├── encryption/            # Encryption interfaces and AES-GCM implementation
│   └── envelope/              # Tink envelope encryption implementation
└── test/integration/          # Integration tests
```

### Encryption Architecture

#### 1. Envelope Encryption (Default - Tink)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Envelope Encryption                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    encrypts    ┌─────────────┐                │
│  │    KEK      │───────────────►│    DEK      │                │
│  │ (in KMS)    │                │ (per object)│                │
│  └─────────────┘                └─────────────┘                │
│                                         │                       │
│                                         │ encrypts               │
│                                         ▼                       │
│                                  ┌─────────────┐                │
│                                  │   Object    │                │
│                                  │    Data     │                │
│                                  └─────────────┘                │
│                                                                 │
│  Storage in S3:                                                 │
│  • Object Data: Encrypted with DEK                             │
│  • Object Metadata: Encrypted DEK + Algorithm Info             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Components:**
- **KEK (Key Encryption Key)**: Master key stored in external KMS (AWS KMS, GCP KMS)
- **DEK (Data Encryption Key)**: Unique AES-256 key generated per S3 object
- **Encrypted DEK**: DEK encrypted with KEK, stored as S3 object metadata
- **Associated Data**: Object key used as additional authenticated data

#### 2. Direct aes-gcm Encryption

```
┌─────────────────────────────────────────────────────────────────┐
│                 Direct aes-gcm Encryption                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    directly encrypts    ┌─────────────┐       │
│  │  Master     │─────────────────────────►│   Object    │       │
│  │   Key       │                          │    Data     │       │
│  │(Static AES) │                          │             │       │
│  └─────────────┘                          └─────────────┘       │
│                                                                 │
│  Storage in S3:                                                 │
│  • Object Data: Encrypted with Master Key                      │
│  • Object Metadata: Algorithm Info + Nonce                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow

### PUT Operation (Encryption)

```
1. Client ───PUT Object──► Proxy
2. Proxy ───Generate DEK──► Encryption Manager
3. Proxy ───Encrypt DEK──► KMS (Tink mode only)
4. Proxy ───Encrypt Data──► Encryption Manager
5. Proxy ───Store Object + Encrypted DEK Metadata──► S3
6. Proxy ───Response──► Client
```

### GET Operation (Decryption)

```
1. Client ───GET Object──► Proxy
2. Proxy ───Fetch Object + Metadata──► S3
3. Proxy ───Decrypt DEK──► KMS (Tink mode only)
4. Proxy ───Decrypt Data──► Encryption Manager
5. Proxy ───Plaintext Response──► Client
```

## Security Model

### Threat Model

**Protected Against:**
- Data at rest exposure (S3 bucket compromise)
- Unauthorized access to encrypted objects
- Key compromise (with envelope encryption)
- Man-in-the-middle attacks (with TLS)

**Security Boundaries:**
- Application runtime (where decrypted data exists)
- KMS service (where KEKs are stored)
- Memory during encryption/decryption operations

### Cryptographic Details

**Envelope Encryption (Tink):**
- Algorithm: aes-gcm (via Google Tink)
- Key Derivation: Tink AEAD primitive
- DEK Generation: Cryptographically secure random
- Associated Data: S3 object key for binding

**Direct Encryption:**
- Algorithm: aes-gcm (Go crypto/aes)
- Key Size: 256 bits
- Nonce: 96-bit random per operation
- Associated Data: S3 object key

## Performance Characteristics

### Memory Usage
- **Streaming**: Large objects processed in chunks
- **DEK Caching**: Minimal memory footprint
- **No Buffering**: Direct stream processing

### Latency
- **Envelope Mode**: +1 KMS call per unique object
- **Direct Mode**: Minimal encryption overhead
- **Concurrent**: Thread-safe operations

### Throughput
- **CPU Bound**: Limited by encryption/decryption speed
- **Network Bound**: Dependent on S3 and KMS latency
- **Scalable**: Stateless service design

## Deployment Architecture

### Standalone Deployment
```
┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
│   Client    │───►│ S3 Encryption   │───►│     S3      │
│             │    │     Proxy       │    │             │
│             │    │   :8080         │    │             │
└─────────────┘    └─────────────────┘    └─────────────┘
```

### Load Balanced Deployment
```
                    ┌─────────────────┐
                 ┌─►│ S3 Encryption   │──┐
┌─────────────┐  │  │ Proxy Instance 1│  │  ┌─────────────┐
│   Client    │──┤  └─────────────────┘  ├─►│     S3      │
│             │  │  ┌─────────────────┐  │  │             │
└─────────────┘  └─►│ S3 Encryption   │──┘  └─────────────┘
                    │ Proxy Instance 2│
                    └─────────────────┘
```

### Container Deployment
```yaml
version: '3.8'
services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com
      - S3EP_ENCRYPTION_TYPE=tink
      - S3EP_KEK_URI=gcp-kms://projects/.../cryptoKeys/...
    volumes:
      - ./credentials.json:/credentials.json:ro
```

## Configuration Architecture

### Configuration Sources (Priority Order)
1. Command line flags
2. Environment variables (prefix: `S3EP_`)
3. Configuration file (YAML/JSON)
4. Default values

### Configuration Schema
```yaml
# Server
bind_address: string
log_level: string

# S3 Backend
target_endpoint: string
region: string
access_key_id: string
secret_key: string

# Encryption
encryption_type: "tink" | "aes256-gcm"
kek_uri: string (Tink mode)
credentials_path: string (Tink mode)
aes_key: string (AES mode)
```

For detailed configuration examples, see [Configuration Guide](./configuration.md).
