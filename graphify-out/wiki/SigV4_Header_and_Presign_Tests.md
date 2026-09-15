# SigV4 Header and Presign Tests

> 23 nodes · cohesion 0.19

## Key Concepts

- **s3auth_presigned_test.go** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **presignTestService()** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
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

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (16 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (4 shared connections)
- [S3auth Presigned](S3auth_Presigned.md) (4 shared connections)
- [SigV4 Service Coverage Tests](SigV4_Service_Coverage_Tests.md) (3 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 65 (86%)
- INFERRED: 11 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*