# Middleware: S3Auth Presigned Test

> 18 nodes · cohesion 0.18

## Key Concepts

- **presignTestService()** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requireAuthErr()** (9 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **presignWithSDK()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requestFromPresignedURL()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedTampering()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
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
- **TestMwPresignedSigningTimeInTheFuture()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestAuthenticateRequest_HeaderPathUnaffected()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **flipLastHexDigit()** (2 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (18 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (18 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Server and Listings](Server_and_Listings.md) (3 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (2 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 61 (84%)
- INFERRED: 12 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*