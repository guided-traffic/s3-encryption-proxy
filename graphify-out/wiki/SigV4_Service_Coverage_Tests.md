# SigV4 Service Coverage Tests

> 20 nodes · cohesion 0.18

## Key Concepts

- **s3auth_coverage_test.go** (17 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwauthService()** (13 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwsignDateHeaderRequest()** (10 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **NewS3AuthenticationService()** (10 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **github.com/sirupsen/logrus.Logger** (4 connections)
- **TestMwAuthenticateRequestDateHeaderPath()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthenticateRequestRejections()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwAuthErrorsCarryTheS3ErrorCodeMarkers()** (4 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBudgetsWithoutConfiguredValues()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalHeaders()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwBuildCanonicalRequestPayloadHash()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwHeaderAuthHonoursTheConfiguredClockSkew()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwMaxPresignExpirySeconds()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwPresignedSigningTimeInTheFuture()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwPresignExpiryHonoursTheConfiguredCeiling()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateSignatureTimestampSources()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwValidateTimestamp()** (3 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwhmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestMwMaxClockSkewSeconds()** (2 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **S3AuthenticationService** (1 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (15 shared connections)
- [S3auth Robust](S3auth_Robust.md) (3 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (3 shared connections)
- [S3auth Presigned](S3auth_Presigned.md) (2 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (1 shared connections)
- [S3 Error Document Writer](S3_Error_Document_Writer.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (1 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 56 (88%)
- INFERRED: 8 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*