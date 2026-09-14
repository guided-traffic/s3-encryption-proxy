# SigV4 Header Authentication

> 15 nodes · cohesion 0.26

## Key Concepts

- **S3AuthenticationService** (16 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **NewS3AuthenticationService()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.AuthenticateRequest()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **SignatureInfo** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **github.com/sirupsen/logrus.Logger** (4 connections)
- **.validateTimestamp()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **s3auth_robust.go** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildCanonicalHeaders()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.calculateSignature()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.logSecurityEvent()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.parseAuthorizationHeader()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildStringToSign()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.hmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [Pre-Signed URL Authentication](Pre-Signed_URL_Authentication.md) (4 shared connections)
- [Config Structure](Config_Structure.md) (3 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (2 shared connections)
- [Backend Error Mapping](Backend_Error_Mapping.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (1 shared connections)
- [CORS Middleware](CORS_Middleware.md) (1 shared connections)
- [SigV4 Coverage Tests](SigV4_Coverage_Tests.md) (1 shared connections)
- [SigV4 Authentication Tests](SigV4_Authentication_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 43 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*