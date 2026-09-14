# SigV4 Authentication Tests

> 23 nodes · cohesion 0.19

## Key Concepts

- **presignTestService()** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **s3auth_presigned_test.go** (14 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requireAuthErr()** (8 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **presignWithSDK()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requestFromPresignedURL()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedTampering()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **s3auth_header_test.go** (6 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **signWithSDK()** (6 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_PresignedExpiry()** (6 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestMwPresignedRejections()** (5 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestAuthenticateRequest_HeaderTampering()** (5 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **rewindSigningTime()** (5 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_SDKPresignedURL()** (5 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_ClockSkew()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_MalformedHeaders()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_SDKSignedHeaders()** (4 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_PresignedMalformed()** (4 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_HeaderPathUnaffected()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **flipLastHexDigit()** (2 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **discardWriter** (2 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **S3AuthenticationService** (1 connections)
- **S3AuthenticationService** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (16 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Pre-Signed URL Authentication](Pre-Signed_URL_Authentication.md) (3 shared connections)
- [SigV4 Coverage Tests](SigV4_Coverage_Tests.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 64 (85%)
- INFERRED: 11 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*