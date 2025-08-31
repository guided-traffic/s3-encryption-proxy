# Configuration Guide

## Overview

The S3 Encryption Proxy supports flexible configuration through multiple sources with clear precedence rules. This guide covers all configuration options and provides practical examples for different deployment scenarios.

## Configuration Sources

Configuration is loaded in the following order (highest to lowest precedence):

1. **Command Line Flags** (highest precedence)
2. **Environment Variables** (prefix: `S3EP_`)
3. **Configuration File** (YAML or JSON)
4. **Default Values** (lowest precedence)

## Configuration Options

### Server Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | string | `"0.0.0.0:8080"` | Address and port to bind the HTTP server |
| `log_level` | string | `"info"` | Logging level (debug, info, warn, error) |

### S3 Backend Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `target_endpoint` | string | Yes | S3 endpoint URL (e.g., `https://s3.amazonaws.com`) |
| `region` | string | Yes | AWS region (e.g., `us-east-1`) |
| `access_key_id` | string | Yes | AWS Access Key ID |
| `secret_key` | string | Yes | AWS Secret Access Key |

### Encryption Configuration

#### General Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `encryption_type` | string | `"tink"` | Encryption mode: `"tink"` or `"aes256-gcm"` |
| `algorithm` | string | `"AES256_GCM"` | Encryption algorithm |
| `metadata_key_prefix` | string | `"x-s3ep-"` | Prefix for encryption metadata in S3 |

#### Tink (Envelope Encryption) Settings

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `kek_uri` | string | Yes (Tink mode) | KMS URI for Key Encryption Key |
| `credentials_path` | string | Yes (Tink mode) | Path to KMS service account credentials |

**Supported KEK URI Formats:**
- Google Cloud KMS: `gcp-kms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY`
- AWS KMS: `aws-kms://arn:aws:kms:REGION:ACCOUNT:key/KEY-ID`

#### AES-256-GCM (Direct Encryption) Settings

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `aes_key` | string | Yes (AES mode) | Base64-encoded 256-bit AES key |

## Configuration Examples

### 1. Tink (Envelope Encryption) Configuration

#### YAML Configuration File
```yaml
# config/tink-production.yaml
bind_address: "0.0.0.0:8080"
log_level: "info"

# S3 backend
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"
access_key_id: "${S3_ACCESS_KEY_ID}"
secret_key: "${S3_SECRET_KEY}"

# Tink envelope encryption
encryption_type: "tink"
kek_uri: "gcp-kms://projects/my-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"
credentials_path: "/etc/s3ep/gcp-credentials.json"

# Metadata settings
metadata_key_prefix: "x-s3ep-"
algorithm: "AES256_GCM"
```

#### Environment Variables
```bash
export S3EP_TARGET_ENDPOINT="https://s3.amazonaws.com"
export S3EP_REGION="us-east-1"
export S3EP_ACCESS_KEY_ID="AKIA..."
export S3EP_SECRET_KEY="..."
export S3EP_ENCRYPTION_TYPE="tink"
export S3EP_KEK_URI="gcp-kms://projects/my-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"
export S3EP_CREDENTIALS_PATH="/etc/s3ep/gcp-credentials.json"
```

#### Command Line
```bash
./s3-encryption-proxy \
  --target-endpoint https://s3.amazonaws.com \
  --region us-east-1 \
  --encryption-type tink \
  --kek-uri "gcp-kms://projects/my-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key" \
  --credentials-path /etc/s3ep/gcp-credentials.json
```

### 2. AES-256-GCM (Direct Encryption) Configuration

#### YAML Configuration File
```yaml
# config/aes-development.yaml
bind_address: "localhost:8080"
log_level: "debug"

# S3 backend
target_endpoint: "http://localhost:9000"  # MinIO
region: "us-east-1"
access_key_id: "minioadmin"
secret_key: "minioadmin"

# Direct AES encryption
encryption_type: "aes256-gcm"
aes_key: "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ=="

# Metadata settings
metadata_key_prefix: "x-s3ep-"
algorithm: "AES256_GCM"
```

#### Environment Variables
```bash
export S3EP_TARGET_ENDPOINT="http://localhost:9000"
export S3EP_REGION="us-east-1"
export S3EP_ACCESS_KEY_ID="minioadmin"
export S3EP_SECRET_KEY="minioadmin"
export S3EP_ENCRYPTION_TYPE="aes256-gcm"
export S3EP_AES_KEY="SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ=="
```

#### Command Line
```bash
./s3-encryption-proxy \
  --target-endpoint http://localhost:9000 \
  --region us-east-1 \
  --encryption-type aes256-gcm \
  --aes-key "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ=="
```

## Key Generation

### Generating AES Keys

For AES-256-GCM mode, you need a 256-bit (32-byte) key. Use the provided key generation tool:

```bash
# Build the key generator
make build-keygen

# Generate a new AES key
./build/s3ep-keygen
```

**Output:**
```
Generated AES-256 key: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==
```

**Alternative methods:**
```bash
# Using OpenSSL
openssl rand -base64 32

# Using Python
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

# Using Go
go run -c "import crypto/rand; import encoding/base64; key := make([]byte, 32); rand.Read(key); fmt.Println(base64.StdEncoding.EncodeToString(key))"
```

### Setting up KMS Keys

#### Google Cloud KMS

1. **Create a key ring:**
```bash
gcloud kms keyrings create s3-encryption \
  --location=global
```

2. **Create a key:**
```bash
gcloud kms keys create master-key \
  --location=global \
  --keyring=s3-encryption \
  --purpose=encryption
```

3. **Get the KEK URI:**
```bash
echo "gcp-kms://projects/$(gcloud config get-value project)/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"
```

#### AWS KMS

1. **Create a key:**
```bash
aws kms create-key \
  --description "S3 Encryption Proxy Master Key" \
  --usage ENCRYPT_DECRYPT
```

2. **Create an alias:**
```bash
aws kms create-alias \
  --alias-name alias/s3-encryption-proxy \
  --target-key-id <key-id-from-step-1>
```

3. **Get the KEK URI:**
```bash
echo "aws-kms://arn:aws:kms:us-east-1:123456789012:key/<key-id>"
```

## Deployment Configurations

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com
      - S3EP_REGION=us-east-1
      - S3EP_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - S3EP_SECRET_KEY=${AWS_SECRET_ACCESS_KEY}
      - S3EP_ENCRYPTION_TYPE=tink
      - S3EP_KEK_URI=${GCP_KEK_URI}
    volumes:
      - ./gcp-credentials.json:/credentials.json:ro
    command: [
      "--credentials-path", "/credentials.json"
    ]
    restart: unless-stopped

  # MinIO for local testing
  minio:
    image: minio/minio:latest
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      - MINIO_ACCESS_KEY=minioadmin
      - MINIO_SECRET_KEY=minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio-data:/data

volumes:
  minio-data:
```

### Kubernetes

```yaml
# kubernetes/deployment.yaml
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
    metadata:
      labels:
        app: s3-encryption-proxy
    spec:
      containers:
      - name: s3-encryption-proxy
        image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
        ports:
        - containerPort: 8080
        env:
        - name: S3EP_TARGET_ENDPOINT
          value: "https://s3.amazonaws.com"
        - name: S3EP_REGION
          value: "us-east-1"
        - name: S3EP_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: aws-credentials
              key: access-key-id
        - name: S3EP_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: aws-credentials
              key: secret-access-key
        - name: S3EP_ENCRYPTION_TYPE
          value: "tink"
        - name: S3EP_KEK_URI
          value: "gcp-kms://projects/my-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"
        - name: S3EP_CREDENTIALS_PATH
          value: "/etc/gcp/credentials.json"
        volumeMounts:
        - name: gcp-credentials
          mountPath: /etc/gcp
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
      volumes:
      - name: gcp-credentials
        secret:
          secretName: gcp-credentials

---
apiVersion: v1
kind: Service
metadata:
  name: s3-encryption-proxy
spec:
  selector:
    app: s3-encryption-proxy
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

## Environment-Specific Configurations

### Development Environment

**File: `config/dev.yaml`**
```yaml
bind_address: "localhost:8080"
log_level: "debug"
target_endpoint: "http://localhost:9000"  # MinIO
region: "us-east-1"
access_key_id: "minioadmin"
secret_key: "minioadmin"
encryption_type: "aes256-gcm"
aes_key: "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ=="
```

### Staging Environment

**File: `config/staging.yaml`**
```yaml
bind_address: "0.0.0.0:8080"
log_level: "info"
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"
access_key_id: "${S3_ACCESS_KEY_ID}"
secret_key: "${S3_SECRET_KEY}"
encryption_type: "tink"
kek_uri: "gcp-kms://projects/staging-project/locations/global/keyRings/s3-encryption/cryptoKeys/staging-key"
credentials_path: "/etc/s3ep/staging-credentials.json"
```

### Production Environment

**File: `config/production.yaml`**
```yaml
bind_address: "0.0.0.0:8080"
log_level: "warn"
target_endpoint: "https://s3.amazonaws.com"
region: "us-east-1"
access_key_id: "${S3_ACCESS_KEY_ID}"
secret_key: "${S3_SECRET_KEY}"
encryption_type: "tink"
kek_uri: "gcp-kms://projects/production-project/locations/global/keyRings/s3-encryption/cryptoKeys/production-key"
credentials_path: "/etc/s3ep/production-credentials.json"
```

## Security Best Practices

### Key Management
- **Never commit keys to version control**
- **Use environment variables or secure secret management**
- **Rotate keys regularly**
- **Use different keys for different environments**

### KMS Configuration
- **Use dedicated KMS keys per environment**
- **Implement proper IAM policies**
- **Enable KMS audit logging**
- **Consider cross-region key replication**

### Network Security
- **Use TLS for all external communications**
- **Implement proper firewall rules**
- **Consider VPC/private networking**
- **Use load balancers with SSL termination**

## Troubleshooting

### Common Configuration Issues

**1. Invalid KEK URI:**
```
Error: failed to create encryption manager: invalid KEK URI format
```
- Verify the KEK URI format matches the KMS provider
- Ensure the key exists and is accessible

**2. Invalid AES Key:**
```
Error: invalid AES key: illegal base64 data
```
- Ensure the key is properly base64 encoded
- Verify the key is exactly 32 bytes (256 bits) when decoded

**3. S3 Connection Issues:**
```
Error: failed to connect to S3: no such host
```
- Verify the target endpoint URL
- Check network connectivity
- Validate AWS credentials

### Configuration Validation

Enable debug logging to see the resolved configuration:

```bash
./s3-encryption-proxy --log-level debug --config config/your-config.yaml
```

This will output the final merged configuration (with sensitive values redacted).

For additional troubleshooting information, see [Troubleshooting Guide](./troubleshooting.md).
