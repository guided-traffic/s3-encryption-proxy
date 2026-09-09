# SigV4 Auth Service Tests

> 17 nodes · cohesion 0.24

## Key Concepts

- **s3auth_coverage_test.go** (16 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwauthService()** (15 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwsignDateHeaderRequest()** (12 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestDateHeaderPath()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestRejections()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthErrorsCarryTheS3ErrorCodeMarkers()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwSecurityMetrics()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwSecurityMetricsUnderConcurrency()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalHeaders()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalRequestPayloadHash()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwGetClientIP()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwPresignedSigningTimeInTheFuture()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateSignatureTimestampSources()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateTimestamp()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwhmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwMaxClockSkewSeconds()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **S3AuthenticationService** (1 connections)

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (3 shared connections)
- [SigV4 Header Auth Tests](SigV4_Header_Auth_Tests.md) (2 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`

## Audit Trail

- EXTRACTED: 50 (93%)
- INFERRED: 4 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*