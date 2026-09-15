# Backend

> 11 nodes · cohesion 0.38

## Key Concepts

- **BackendClient()** (19 connections) — `test/e2e/harness/backend.go`
- **harness/backend.go** (10 connections) — `test/e2e/harness/backend.go`
- **ProxyClient()** (10 connections) — `test/e2e/harness/backend.go`
- **EmptyAndDeleteBucket()** (8 connections) — `test/e2e/harness/backend.go`
- **ReadViaProxy()** (8 connections) — `test/e2e/harness/backend.go`
- **EnsureBucket()** (7 connections) — `test/e2e/harness/backend.go`
- **EmptyBucket()** (6 connections) — `test/e2e/harness/backend.go`
- **s3Client()** (6 connections) — `test/e2e/harness/backend.go`
- **caTrustingHTTPClient()** (5 connections) — `test/e2e/harness/backend.go`
- **OpenUploads()** (5 connections) — `test/e2e/harness/backend.go`
- **ProxyETag()** (5 connections) — `test/e2e/harness/backend.go`

## Relationships

- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (11 shared connections)
- [rclone E2E Suite](rclone_E2E_Suite.md) (10 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (10 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (6 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (3 shared connections)
- [Harness](Harness.md) (3 shared connections)
- [Scenarios Atrest](Scenarios_Atrest.md) (2 shared connections)
- [Scenarios Read](Scenarios_Read.md) (1 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)

## Source Files

- `test/e2e/harness/backend.go`

## Audit Trail

- EXTRACTED: 65 (96%)
- INFERRED: 3 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*