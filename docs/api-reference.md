# API Reference

## Overview

The S3 Encryption Proxy provides a fully compatible S3 API interface that transparently handles encryption and decryption of objects. All standard S3 operations are supported with automatic encryption/decryption applied.

## Base URL

The proxy runs on configurable address and port (default: `http://localhost:8080`).

## Authentication

The proxy uses S3-compatible authentication:
- **AWS Signature Version 4** (recommended)
- **AWS Signature Version 2** (deprecated, for legacy support)

Authentication credentials are passed through to the backend S3 service.

## Supported Operations

### Object Operations

#### PUT Object

Stores an object with automatic encryption.

**Request:**
```http
PUT /{bucket}/{key} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
Content-Type: application/octet-stream
Content-Length: 1024

[Binary data]
```

**Response:**
```http
HTTP/1.1 200 OK
ETag: "abc123def456"
x-s3ep-encrypted: true
x-s3ep-algorithm: AES256_GCM

<PutObjectResult>
  <ETag>"abc123def456"</ETag>
</PutObjectResult>
```

**Encryption Process:**
1. Generate Data Encryption Key (DEK) or use master key
2. Encrypt object data with DEK/master key
3. Store encrypted DEK in object metadata (envelope mode)
4. Store encrypted object in S3

#### GET Object

Retrieves and decrypts an object.

**Request:**
```http
GET /{bucket}/{key} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1024
ETag: "abc123def456"
Last-Modified: Mon, 15 Jan 2024 10:30:00 GMT

[Decrypted binary data]
```

**Decryption Process:**
1. Retrieve encrypted object and metadata from S3
2. Extract encryption information from metadata
3. Decrypt DEK with KEK (envelope mode) or use master key
4. Decrypt object data with DEK/master key
5. Return plaintext data to client

#### HEAD Object

Returns object metadata without the object data.

**Request:**
```http
HEAD /{bucket}/{key} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1024
ETag: "abc123def456"
Last-Modified: Mon, 15 Jan 2024 10:30:00 GMT
x-s3ep-encrypted: true
x-s3ep-algorithm: AES256_GCM
```

#### DELETE Object

Deletes an object (passthrough operation).

**Request:**
```http
DELETE /{bucket}/{key} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 204 No Content
```

### Bucket Operations

#### LIST Objects

Lists objects in a bucket (passthrough operation).

**Request:**
```http
GET /{bucket}?list-type=2 HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/xml

<ListBucketResult>
  <Name>my-bucket</Name>
  <Contents>
    <Key>file1.txt</Key>
    <Size>1024</Size>
    <ETag>"abc123def456"</ETag>
    <LastModified>2024-01-15T10:30:00.000Z</LastModified>
  </Contents>
</ListBucketResult>
```

#### CREATE Bucket

Creates a new bucket (passthrough operation).

**Request:**
```http
PUT /{bucket} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 200 OK
Location: /my-bucket
```

#### DELETE Bucket

Deletes a bucket (passthrough operation).

**Request:**
```http
DELETE /{bucket} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Response:**
```http
HTTP/1.1 204 No Content
```

## Encryption Metadata

The proxy stores encryption-related metadata as S3 object metadata with configurable prefix (default: `x-s3ep-`).

### Envelope Encryption Metadata

```http
x-s3ep-encrypted-key: base64-encoded-encrypted-dek
x-s3ep-algorithm: AES256_GCM
x-s3ep-key-version: 1
x-s3ep-encryption-type: tink
x-s3ep-created: 2024-01-15T10:30:00Z
```

### Direct AES Encryption Metadata

```http
x-s3ep-algorithm: AES256_GCM
x-s3ep-nonce: base64-encoded-nonce
x-s3ep-encryption-type: aes256-gcm
x-s3ep-created: 2024-01-15T10:30:00Z
```

## Health and Status Endpoints

### Health Check

Returns the overall health status of the proxy.

**Request:**
```http
GET /health HTTP/1.1
Host: localhost:8080
```

**Response (Healthy):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "encryption_type": "tink",
  "s3_backend": "connected"
}
```

**Response (Unhealthy):**
```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "status": "unhealthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "error": "unable to connect to S3 backend"
}
```

### Readiness Check

Returns whether the proxy is ready to serve traffic.

**Request:**
```http
GET /ready HTTP/1.1
Host: localhost:8080
```

**Response (Ready):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Metrics (Optional)

If metrics are enabled, Prometheus-compatible metrics are available.

**Request:**
```http
GET /metrics HTTP/1.1
Host: localhost:8080
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8

# HELP s3_requests_total Total number of S3 requests
# TYPE s3_requests_total counter
s3_requests_total{method="GET",status="200"} 150
s3_requests_total{method="PUT",status="200"} 75

# HELP s3_encryption_operations_total Total number of encryption operations
# TYPE s3_encryption_operations_total counter
s3_encryption_operations_total{operation="encrypt",status="success"} 75
s3_encryption_operations_total{operation="decrypt",status="success"} 150
```

## Error Responses

The proxy returns standard S3 error responses with additional encryption-specific errors.

### Standard S3 Errors

**NoSuchBucket:**
```http
HTTP/1.1 404 Not Found
Content-Type: application/xml

<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
  <BucketName>nonexistent-bucket</BucketName>
  <RequestId>abc123def456</RequestId>
</Error>
```

**NoSuchKey:**
```http
HTTP/1.1 404 Not Found
Content-Type: application/xml

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist</Message>
  <Key>nonexistent-key</Key>
  <RequestId>abc123def456</RequestId>
</Error>
```

**AccessDenied:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/xml

<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>abc123def456</RequestId>
</Error>
```

### Encryption-Specific Errors

**EncryptionError:**
```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/xml

<Error>
  <Code>InternalError</Code>
  <Message>An internal error occurred during encryption</Message>
  <RequestId>abc123def456</RequestId>
</Error>
```

**KeyNotFound:**
```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/xml

<Error>
  <Code>InternalError</Code>
  <Message>Encryption key not found or inaccessible</Message>
  <RequestId>abc123def456</RequestId>
</Error>
```

**InvalidEncryptionMetadata:**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/xml

<Error>
  <Code>InvalidRequest</Code>
  <Message>Invalid or missing encryption metadata</Message>
  <RequestId>abc123def456</RequestId>
</Error>
```

## Client Configuration

### AWS CLI

Configure AWS CLI to use the proxy:

```bash
# Configure AWS CLI
aws configure set aws_access_key_id YOUR_ACCESS_KEY
aws configure set aws_secret_access_key YOUR_SECRET_KEY
aws configure set region us-east-1

# Use proxy endpoint
aws s3 --endpoint-url http://localhost:8080 ls s3://my-bucket/
aws s3 --endpoint-url http://localhost:8080 cp file.txt s3://my-bucket/
```

### Python boto3

```python
import boto3

# Create S3 client with proxy endpoint
s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:8080',
    aws_access_key_id='YOUR_ACCESS_KEY',
    aws_secret_access_key='YOUR_SECRET_KEY',
    region_name='us-east-1'
)

# Use normally - encryption is transparent
response = s3_client.put_object(
    Bucket='my-bucket',
    Key='my-file.txt',
    Body=b'Hello, encrypted world!'
)

# Retrieve object (automatically decrypted)
response = s3_client.get_object(Bucket='my-bucket', Key='my-file.txt')
data = response['Body'].read()
print(data.decode('utf-8'))  # Output: Hello, encrypted world!
```

### Java AWS SDK

```java
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.net.URI;

// Create S3 client with proxy endpoint
S3Client s3Client = S3Client.builder()
    .endpointOverride(URI.create("http://localhost:8080"))
    .credentialsProvider(StaticCredentialsProvider.create(
        AwsBasicCredentials.create("YOUR_ACCESS_KEY", "YOUR_SECRET_KEY")))
    .region(Region.US_EAST_1)
    .build();

// Use normally - encryption is transparent
PutObjectRequest putRequest = PutObjectRequest.builder()
    .bucket("my-bucket")
    .key("my-file.txt")
    .build();

s3Client.putObject(putRequest, RequestBody.fromString("Hello, encrypted world!"));
```

### Go AWS SDK

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "log"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
    // Create S3 client with proxy endpoint
    cfg, err := config.LoadDefaultConfig(context.TODO(),
        config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
            "YOUR_ACCESS_KEY", "YOUR_SECRET_KEY", "")),
        config.WithRegion("us-east-1"),
    )
    if err != nil {
        log.Fatal(err)
    }

    client := s3.NewFromConfig(cfg, func(o *s3.Options) {
        o.BaseEndpoint = aws.String("http://localhost:8080")
    })

    // Use normally - encryption is transparent
    _, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
        Bucket: aws.String("my-bucket"),
        Key:    aws.String("my-file.txt"),
        Body:   bytes.NewReader([]byte("Hello, encrypted world!")),
    })
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve object (automatically decrypted)
    result, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
        Bucket: aws.String("my-bucket"),
        Key:    aws.String("my-file.txt"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer result.Body.Close()

    // Read decrypted data
    data := make([]byte, 1024)
    n, _ := result.Body.Read(data)
    fmt.Println(string(data[:n])) // Output: Hello, encrypted world!
}
```

## Rate Limiting and Quotas

The proxy respects S3 backend rate limits and quotas. Additional rate limiting can be implemented at the load balancer or reverse proxy level.

## Caching

The proxy does not cache decrypted data for security reasons. Each request results in:
1. Retrieval from S3 backend
2. Decryption operation
3. Response to client

For performance optimization, implement caching at the client level or use appropriate S3 backend caching strategies.

## Multipart Upload Support

The proxy supports S3 multipart uploads with encryption applied to each part:

**Initiate Multipart Upload:**
```http
POST /{bucket}/{key}?uploads HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

**Upload Part:**
```http
PUT /{bucket}/{key}?partNumber=1&uploadId=abc123 HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
Content-Length: 5242880

[Part data - will be encrypted]
```

**Complete Multipart Upload:**
```http
POST /{bucket}/{key}?uploadId=abc123 HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...

<CompleteMultipartUpload>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"abc123"</ETag>
  </Part>
</CompleteMultipartUpload>
```

## Versioning Support

The proxy supports S3 object versioning. Each version is encrypted independently:

**Put Object with Versioning:**
```http
PUT /{bucket}/{key} HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...

[Object data - each version encrypted independently]
```

**Get Specific Version:**
```http
GET /{bucket}/{key}?versionId=abc123 HTTP/1.1
Host: localhost:8080
Authorization: AWS4-HMAC-SHA256 Credential=...
```

## Performance Considerations

### Throughput

- **Encryption Overhead**: ~5-10% CPU overhead for aes-gcm
- **Network Overhead**: Minimal (metadata only)
- **Memory Usage**: Streaming operations minimize memory footprint

### Latency

- **Envelope Mode**: +1 KMS round-trip per unique object
- **Direct Mode**: Minimal encryption latency
- **Caching**: DEK caching reduces KMS calls

### Optimization Tips

1. **Use Direct Mode** for lower latency (no KMS dependency)
2. **Implement Client-Side Caching** for frequently accessed objects
3. **Use Connection Pooling** for better performance
4. **Monitor KMS Quotas** in envelope mode

For detailed performance benchmarks and optimization guides, see [Performance Guide](./performance.md).
