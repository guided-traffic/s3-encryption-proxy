# S3 Client Authentication

## Overview

The S3 Encryption Proxy now supports client authentication to restrict access to only authorized S3 clients. This feature allows you to configure a list of allowed client credentials that can connect to and use the proxy.

## Configuration

Add the `s3_clients` section to your configuration file to enable client authentication:

```yaml
# S3 Client Authentication Configuration
# If this section is not configured, all clients are allowed (backward compatibility)
# Only clients with valid credentials listed here can connect to the proxy
s3_clients:
  - type: "static"
    access_key_id: "AABBCCDDEEFF"
    secret_key: "AABBCCDDEEFF"
    description: "Production client credentials"
  - type: "static"
    access_key_id: "testclient123"
    secret_key: "testsecret456"
    description: "Test client for development"
```

### Configuration Fields

- **`type`**: Authentication type. Currently only `"static"` is supported.
- **`access_key_id`**: The S3 access key ID that the client must use.
- **`secret_key`**: The S3 secret access key that the client must use.
- **`description`**: Optional description for documentation purposes.

## Behavior

### Authentication Enabled
When `s3_clients` is configured with one or more entries:

1. **Valid Credentials**: Clients using configured `access_key_id` and `secret_key` combinations are allowed access.
2. **Invalid Credentials**: Clients using unknown `access_key_id` values receive an `InvalidAccessKeyId` error.
3. **Missing Authorization**: Requests without proper AWS signature authentication receive an `AccessDenied` error.

### Authentication Disabled (Backward Compatibility)
When `s3_clients` is not configured or is empty:

- All clients are allowed to connect (backward compatibility)
- No authentication is performed
- The proxy behaves as it did before this feature was added

### Health Endpoints Exception
The `/health` and `/version` endpoints are always accessible without authentication, regardless of the authentication configuration.

## Examples

### Example 1: Basic Authentication
```yaml
s3_clients:
  - type: "static"
    access_key_id: "myapp-prod"
    secret_key: "my-super-secret-key"
    description: "Production application"
```

### Example 2: Multiple Clients
```yaml
s3_clients:
  - type: "static"
    access_key_id: "frontend-app"
    secret_key: "frontend-secret-2024"
    description: "Frontend application"
  - type: "static"
    access_key_id: "backend-service"
    secret_key: "backend-secret-2024"
    description: "Backend service"
  - type: "static"
    access_key_id: "data-pipeline"
    secret_key: "pipeline-secret-2024"
    description: "Data processing pipeline"
```

### Example 3: Disabled Authentication (Default)
```yaml
# No s3_clients section = authentication disabled
# OR
s3_clients: []  # Empty list = authentication disabled
```

## Client Configuration

Configure your S3 clients to use the credentials defined in the proxy configuration:

### AWS CLI
```bash
aws configure set aws_access_key_id AABBCCDDEEFF
aws configure set aws_secret_access_key AABBCCDDEEFF
aws configure set region us-east-1

# Use the proxy endpoint
aws s3 ls --endpoint-url http://your-proxy:8080
```

### AWS SDK (Go)
```go
cfg, err := config.LoadDefaultConfig(context.Background(),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        "AABBCCDDEEFF", // access_key_id from proxy config
        "AABBCCDDEEFF", // secret_key from proxy config
        "",
    )),
    config.WithRegion("us-east-1"),
)

s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("http://your-proxy:8080")
    o.UsePathStyle = true
})
```

### AWS SDK (Python)
```python
import boto3

s3 = boto3.client(
    's3',
    endpoint_url='http://your-proxy:8080',
    aws_access_key_id='AABBCCDDEEFF',
    aws_secret_access_key='AABBCCDDEEFF',
    region_name='us-east-1'
)
```

## Security Considerations

### Important Security Notes

1. **Credentials Storage**: Store client credentials securely and rotate them regularly.

2. **Network Security**: Use HTTPS/TLS when deploying in production to protect credentials in transit.

3. **Access Logging**: The proxy logs authentication attempts for security monitoring.

4. **Credential Rotation**: Plan for credential rotation - clients will need updated credentials when rotated.

5. **Principle of Least Privilege**: Create separate credentials for different applications/services rather than sharing credentials.

### Production Recommendations

```yaml
# Production configuration example
s3_clients:
  - type: "static"
    access_key_id: "prod-webapp-2024"
    secret_key: "{{ .Env.WEBAPP_S3_SECRET }}"  # Use environment variables
    description: "Production web application"
  - type: "static"
    access_key_id: "prod-backend-2024"
    secret_key: "{{ .Env.BACKEND_S3_SECRET }}"  # Use environment variables
    description: "Production backend service"
```

## Error Responses

### Invalid Access Key ID
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InvalidAccessKeyId</Code>
    <Message>The AWS Access Key Id you provided does not exist in our records.</Message>
    <RequestId>s3-encryption-proxy</RequestId>
</Error>
```

### Access Denied (Missing Authorization)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
    <RequestId>s3-encryption-proxy</RequestId>
</Error>
```

### Signature Mismatch
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>SignatureDoesNotMatch</Code>
    <Message>The request signature we calculated does not match the signature you provided.</Message>
    <RequestId>s3-encryption-proxy</RequestId>
</Error>
```

## Logging

The proxy logs authentication events for monitoring and debugging:

```
time="2025-09-15T14:28:53Z" level=warning msg="S3 authentication failed: invalid signature" access_key_id=AABBCCDDEEFF error="signature mismatch" method=GET path=/
time="2025-09-15T14:29:15Z" level=warning msg="S3 authentication failed: unknown access key" access_key_id=unknownkey method=GET path=/
time="2025-09-15T14:29:30Z" level=debug msg="S3 client authenticated successfully" access_key_id=AABBCCDDEEFF method=GET path=/ description="Demo client credentials"
```

## Migration from Unauthenticated Setup

The S3 client authentication feature is fully backward compatible:

1. **Default Behavior**: If no `s3_clients` configuration is present, all clients continue to work as before.
2. **Gradual Migration**: You can enable authentication incrementally by adding the configuration.
3. **Testing**: Test with authentication enabled in a staging environment before production deployment.

## Future Enhancements

Planned future enhancements include:

- **Dynamic Authentication**: Integration with external authentication providers (LDAP, OAuth, etc.)
- **Time-based Access**: Temporary credentials with expiration times
- **IP-based Restrictions**: Combine credentials with IP address restrictions
- **Rate Limiting**: Per-client rate limiting capabilities
