# MinIO Integration Test Suite

> 437 nodes · cohesion 0.02

## Key Concepts

- **.String()** (519 connections) — `test/integration/s3-methods/range_conformance_test.go`
- **.Close()** (119 connections) — `internal/monitoring/server_coverage_test.go`
- **.Cleanup()** (97 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.CleanupTestBucket()** (93 connections) — `/Users/hfi/repos/s3-encryption-proxy/test/integration/authentication/auth_test.go`
- **EnsureMinIOAndProxyAvailable()** (83 connections) — `test/integration/minio_test_helper.go`
- **.GetObject()** (66 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **NewTestContextWithTimeout()** (65 connections) — `test/integration/minio_test_helper.go`
- **.HeadObject()** (58 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutObject()** (54 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **RandomString()** (53 connections) — `test/integration/minio_test_helper.go`
- **.DeleteObject()** (43 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.Read()** (41 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEncEveryPutPathStoresCiphertext()** (32 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **encryption_at_rest_test.go** (32 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **createMinIOClient()** (31 connections) — `test/integration/minio_test_helper.go`
- **CreateTestBucket()** (31 connections) — `test/integration/minio_test_helper.go`
- **TestMpuThreePartRoundTrip()** (30 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **delete_objects_batch_test.go** (29 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **.ListObjectsV2()** (28 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **minio_test_helper.go** (28 connections) — `test/integration/minio_test_helper.go`
- **Manager.EncryptCTR** (27 connections) — `internal/orchestration/singlepart.go`
- **multipart_conformance_test.go** (26 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **createProxyClient()** (25 connections) — `test/integration/minio_test_helper.go`
- **TestEncAWSChunkedFramingStoresCiphertext()** (24 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestMpuPartsUploadedOutOfOrder()** (23 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- *... and 412 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/test/integration/180-degree-variants/large_multipart_upload_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/authentication/auth_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption-modes/aes_provider_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption-modes/none_provider_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption-modes/rsa_provider_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption-modes/test_helpers.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/encryption_validation_helper.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/performance-test/streaming_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/delete_object_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/passthrough_operations_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3_signing_helper.go`
- `docs/architecture/callgraph_orchestration_layer.svg`
- `docs/tickets/018-listobjectsv2-document.md`
- `internal/config/config.go`
- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`
- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`
- `internal/orchestration/manager.go`

## Audit Trail

- EXTRACTED: 2159 (42%)
- INFERRED: 3020 (58%)
- AMBIGUOUS: 11 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*