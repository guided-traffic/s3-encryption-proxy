# S3 Error Response Layer

> 458 nodes · cohesion 0.01

## Key Concepts

- **.Error()** (609 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **.get()** (490 connections) — `test/e2e/velero/exec.go`
- **MockS3Backend** (63 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (63 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **MockS3Backend** (63 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **MockS3Backend** (61 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.WriteS3Error()** (60 connections) — `internal/proxy/response/errors.go`
- **.WriteHeader()** (44 connections) — `internal/monitoring/middleware.go`
- **.WriteNotImplemented()** (41 connections) — `internal/proxy/response/errors.go`
- **MapError()** (37 connections) — `internal/proxy/response/error_mapping.go`
- **Handler** (37 connections) — `internal/proxy/handlers/object/helpers.go`
- **.WriteXML()** (33 connections) — `internal/proxy/response/xml.go`
- **.WriteGenericError()** (25 connections) — `internal/proxy/response/errors.go`
- **error_mapping_coverage_test.go** (22 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **.putObjectStreamingReader()** (19 connections) — `internal/proxy/handlers/object/operations.go`
- **RespCapturingLogger()** (18 connections) — `internal/proxy/response/error_mapping_coverage_test.go`
- **.handleGetObjectRange()** (18 connections) — `internal/proxy/handlers/object/range.go`
- **.handleGetObject()** (17 connections) — `internal/proxy/handlers/object/operations.go`
- **.handlePutObject()** (17 connections) — `internal/proxy/handlers/object/operations.go`
- **error_mapping_test.go** (16 connections) — `internal/proxy/response/error_mapping_test.go`
- **xml_coverage_test.go** (16 connections) — `internal/proxy/response/xml_coverage_test.go`
- **.serveRangeByFullDecryption()** (16 connections) — `internal/proxy/handlers/object/range.go`
- **TestErrorWriter_HostileInputStaysWellFormedXML()** (15 connections) — `internal/proxy/response/errors_test.go`
- **.putObjectDirect()** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **.handleDeleteObjects()** (12 connections) — `internal/proxy/handlers/object/operations.go`
- *... and 433 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/singlepart.go`
- `docs/tickets/022-s3-surface-fidelity.md`
- `internal/monitoring/middleware.go`
- `internal/orchestration/manager.go`
- `internal/orchestration/metadata.go`
- `internal/orchestration/rangeread.go`
- `internal/proxy/handlers/bucket/accelerate.go`
- `internal/proxy/handlers/bucket/acl.go`
- `internal/proxy/handlers/bucket/cors.go`
- `internal/proxy/handlers/bucket/lifecycle.go`
- `internal/proxy/handlers/bucket/location.go`
- `internal/proxy/handlers/bucket/logging.go`
- `internal/proxy/handlers/bucket/notification.go`
- `internal/proxy/handlers/bucket/policy.go`
- `internal/proxy/handlers/bucket/replication.go`
- `internal/proxy/handlers/bucket/request_payment.go`
- `internal/proxy/handlers/bucket/tagging.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/bucket/versioning.go`
- `internal/proxy/handlers/bucket/website.go`

## Audit Trail

- EXTRACTED: 1192 (34%)
- INFERRED: 2354 (66%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*