# SigV4 Authentication

> 101 nodes · cohesion 0.05

## Key Concepts

- **.AuthenticateRequest()** (25 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **S3AuthenticationService** (19 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **s3auth_coverage_test.go** (16 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **s3auth_presigned_test.go** (14 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **presignTestService()** (14 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **S3AuthenticationService.AuthenticateRequest (SigV4 entry)** (14 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **TestMwPresignedRejections()** (13 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **.authenticatePresigned()** (12 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **MwauthService()** (12 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestRejections()** (12 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthErrorsCarryTheS3ErrorCodeMarkers()** (12 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestAuthenticateRequest_PresignedExpiry()** (12 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedTampering()** (12 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **buildCanonicalRequest (payload hash)** (12 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **IsAWSProtocolQueryParam()** (11 connections) — `internal/proxy/request/queryparams.go`
- **MwsignDateHeaderRequest()** (11 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestDateHeaderPath()** (11 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwSecurityMetrics()** (11 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestAuthenticateRequest_HeaderTampering()** (11 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **TestAuthenticateRequest_SDKSignedHeaders()** (11 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **authenticatePresigned** (11 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **truncate()** (10 connections) — `test/e2e/velero/exec.go`
- **buildPresignedCanonicalRequest** (10 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **canonicalQueryString()** (9 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **canonicalURI()** (9 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- *... and 76 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`
- `internal/proxy/middleware/s3auth_robust.go`
- `internal/proxy/request/queryparams.go`
- `internal/proxy/request/queryparams_test.go`
- `test/e2e/velero/exec.go`

## Audit Trail

- EXTRACTED: 403 (63%)
- INFERRED: 234 (36%)
- AMBIGUOUS: 5 (1%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*