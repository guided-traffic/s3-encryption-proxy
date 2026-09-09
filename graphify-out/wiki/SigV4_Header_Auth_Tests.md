# SigV4 Header Auth Tests

> 21 nodes · cohesion 0.20

## Key Concepts

- **presignTestService()** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **s3auth_presigned_test.go** (14 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **presignWithSDK()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requestFromPresignedURL()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **signWithSDK()** (6 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_PresignedExpiry()** (6 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedTampering()** (6 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestMwPresignedRejections()** (5 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **s3auth_header_test.go** (5 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **rewindSigningTime()** (5 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_SDKPresignedURL()** (5 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_ClockSkew()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_HeaderTampering()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_SDKSignedHeaders()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_MalformedHeaders()** (3 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_HeaderPathUnaffected()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedMalformed()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **flipLastHexDigit()** (2 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **discardWriter** (2 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **S3AuthenticationService** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (15 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [SigV4 Auth Service Tests](SigV4_Auth_Service_Tests.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 58 (87%)
- INFERRED: 9 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*