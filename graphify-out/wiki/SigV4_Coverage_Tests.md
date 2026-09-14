# SigV4 Coverage Tests

> 14 nodes · cohesion 0.26

## Key Concepts

- **s3auth_coverage_test.go** (13 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwauthService()** (12 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwsignDateHeaderRequest()** (10 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestDateHeaderPath()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestRejections()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthErrorsCarryTheS3ErrorCodeMarkers()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalHeaders()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalRequestPayloadHash()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwPresignedSigningTimeInTheFuture()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateSignatureTimestampSources()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateTimestamp()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwhmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwMaxClockSkewSeconds()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **S3AuthenticationService** (1 connections)

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (11 shared connections)
- [SigV4 Authentication Tests](SigV4_Authentication_Tests.md) (2 shared connections)
- [Pre-Signed URL Authentication](Pre-Signed_URL_Authentication.md) (2 shared connections)
- [License Logging](License_Logging.md) (1 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (1 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`

## Audit Trail

- EXTRACTED: 39 (91%)
- INFERRED: 4 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*