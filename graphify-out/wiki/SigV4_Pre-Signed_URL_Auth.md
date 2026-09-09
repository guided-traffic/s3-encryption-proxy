# SigV4 Pre-Signed URL Auth

> 35 nodes · cohesion 0.11

## Key Concepts

- **S3AuthenticationService** (22 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.AuthenticateRequest()** (8 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalQueryString()** (7 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **NewS3AuthenticationService()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **s3auth_presigned.go** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.authenticatePresigned()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildPresignedCanonicalRequest()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.validateTimestamp()** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **SignatureInfo** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **github.com/sirupsen/logrus.Logger** (4 connections)
- **S3AuthenticationService** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **uriEncode()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **s3auth_robust.go** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.logSecurityEvent()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.recordMetric()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validatePresignExpiry()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **SecurityMetrics** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **isPresignedRequest()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **parseCredentialScope()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **TestCanonicalQueryString()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalURI()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestURIEncode()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- *... and 10 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (10 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (4 shared connections)
- [SigV4 Header Auth Tests](SigV4_Header_Auth_Tests.md) (4 shared connections)
- [SigV4 Auth Service Tests](SigV4_Auth_Service_Tests.md) (3 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (3 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (3 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (2 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (1 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (1 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`
- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 85 (89%)
- INFERRED: 10 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*