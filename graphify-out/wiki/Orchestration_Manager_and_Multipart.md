# Orchestration Manager and Multipart

> 320 nodes · cohesion 0.03

## Key Concepts

- **contains()** (397 connections) — `internal/validation/hkdf_test.go`
- **multipart_test.go** (54 connections) — `internal/orchestration/multipart_test.go`
- **Manager** (54 connections) — `internal/orchestration/rangeread.go`
- **.InitiateSession()** (52 connections) — `internal/orchestration/multipart.go`
- **createTestMultipartOperations()** (48 connections) — `internal/orchestration/multipart_test.go`
- **OrcPartAESConfig()** (47 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **createTestMultipartConfig()** (42 connections) — `internal/orchestration/multipart_test.go`
- **OrcPartPayload()** (42 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **NewManager()** (40 connections) — `internal/orchestration/manager.go`
- **NewMetadataManager()** (38 connections) — `internal/orchestration/metadata.go`
- **manager_coverage_test.go** (37 connections) — `internal/orchestration/manager_coverage_test.go`
- **.ProcessPart()** (34 connections) — `internal/orchestration/multipart.go`
- **singlepart_coverage_test.go** (33 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **.FinalizeSession()** (33 connections) — `internal/orchestration/multipart.go`
- **OrcPartReader()** (31 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **metadata_coverage_test.go** (30 connections) — `internal/orchestration/metadata_coverage_test.go`
- **multipart_coverage_test.go** (30 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartNewMultipartOps()** (30 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcMgrAESConfig()** (28 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNewManager()** (28 connections) — `internal/orchestration/manager_coverage_test.go`
- **.EncryptCTR()** (28 connections) — `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/singlepart.go`
- **.GetSessionCount()** (28 connections) — `internal/orchestration/manager.go`
- **.DecryptData()** (27 connections) — `internal/orchestration/manager.go`
- **MetadataManager** (27 connections) — `internal/orchestration/metadata.go`
- **OrcMetaConfig()** (25 connections) — `internal/orchestration/metadata_coverage_test.go`
- *... and 295 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/providers_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/singlepart.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_location_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/test/integration/s3-methods/bucket_subresource_test.go`
- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`
- `internal/orchestration/metadata.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/metadata_test.go`
- `internal/orchestration/multipart.go`
- `internal/orchestration/multipart_coverage_test.go`
- `internal/orchestration/multipart_test.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/rangeread.go`
- `internal/orchestration/singlepart_coverage_test.go`
- `internal/validation/hkdf_test.go`
- `internal/validation/hmac_manager.go`

## Audit Trail

- EXTRACTED: 1854 (51%)
- INFERRED: 1769 (49%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*