# SigV4 Header and Presign Tests

> 77 nodes · cohesion 0.05

## Key Concepts

- **s3auth_coverage_test.go** (17 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **S3AuthenticationService** (16 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **s3auth_presigned_test.go** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **presignTestService()** (15 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **MwauthService()** (13 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **MwsignDateHeaderRequest()** (10 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **NewS3AuthenticationService()** (10 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **requireAuthErr()** (8 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **canonicalQueryString()** (8 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **s3auth_robust.go** (8 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **presignWithSDK()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **requestFromPresignedURL()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestAuthenticateRequest_PresignedTampering()** (7 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **.AuthenticateRequest()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **s3auth_header_test.go** (6 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **signWithSDK()** (6 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **s3auth_presigned.go** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **TestAuthenticateRequest_PresignedExpiry()** (6 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **TestMwPresignedRejections()** (5 connections) — `internal/proxy/middleware/s3auth_coverage_test.go`
- **TestAuthenticateRequest_HeaderTampering()** (5 connections) — `internal/proxy/middleware/s3auth_header_test.go`
- **S3AuthenticationService** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **rewindSigningTime()** (5 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- *... and 52 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (35 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (14 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (5 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (4 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)
- [Backend Client](Backend_Client.md) (1 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (1 shared connections)
- [S3 Error Document Writer](S3_Error_Document_Writer.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [Config Env Var Expansion](Config_Env_Var_Expansion.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)

## Source Files

- `docs/security/request-authentication.md`
- `docs/security/tenancy-and-privilege.md`
- `internal/proxy/middleware/s3auth_coverage_test.go`
- `internal/proxy/middleware/s3auth_header_test.go`
- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`
- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 194 (89%)
- INFERRED: 25 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*