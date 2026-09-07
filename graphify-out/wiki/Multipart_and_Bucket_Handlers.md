# Multipart and Bucket Handlers

> 301 nodes · cohesion 0.02

## Key Concepts

- **run()** (626 connections) — `test/e2e/velero/exec.go`
- **.Handle()** (142 connections) — `internal/proxy/handlers/multipart/complete.go`
- **NewErrorWriter()** (72 connections) — `internal/proxy/response/errors.go`
- **multipart_coverage_test.go** (63 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **NewXMLWriter()** (57 connections) — `internal/proxy/response/xml.go`
- **NewParser()** (48 connections) — `internal/proxy/request/parser.go`
- **MpuNewEnv()** (46 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **NewBaseSubResourceHandler()** (43 connections) — `internal/proxy/handlers/bucket/base.go`
- **MpuVars()** (34 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuInitiate()** (28 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **setupMultipartTestEnv()** (24 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **multipart_test.go** (22 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.upload()** (20 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **writeXMLDocument()** (18 connections) — `internal/proxy/handlers/multipart/xml.go`
- **MpuParseError()** (16 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **testHandler()** (16 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **NewCreateHandler()** (15 connections) — `internal/proxy/handlers/multipart/create.go`
- **.MpuUploadPart()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.complete()** (14 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestRespWriteXMLCommitsStatusBeforeMarshalCanFail()** (14 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestMpuAbortKnownUploadReturns204AndClearsSession()** (13 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCreateAbortsBackendUploadWhenEncryptionInitFails()** (13 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuUploadOutOfOrderPartParksTheRequestGoroutine()** (13 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMultipartHandlers_Integration()** (13 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **auth_test.go** (13 connections) — `/Users/hfi/repos/s3-encryption-proxy/test/integration/authentication/auth_test.go`
- *... and 276 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/test/integration/authentication/auth_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_acl_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_cors_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_logging_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_policy_test.go`
- `internal/config/optimizations_test.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/orchestration/manager.go`
- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/accelerate_test.go`
- `internal/proxy/handlers/bucket/acl_test.go`
- `internal/proxy/handlers/bucket/base.go`
- `internal/proxy/handlers/bucket/bucket_crud_test.go`
- `internal/proxy/handlers/bucket/cors_test.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/lifecycle_test.go`
- `internal/proxy/handlers/bucket/location_test.go`
- `internal/proxy/handlers/bucket/logging_test.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/notification_test.go`

## Audit Trail

- EXTRACTED: 1059 (35%)
- INFERRED: 2000 (65%)
- AMBIGUOUS: 3 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*