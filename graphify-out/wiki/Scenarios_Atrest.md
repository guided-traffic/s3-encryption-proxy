# Scenarios Atrest

> 15 nodes · cohesion 0.19

## Key Concepts

- **TestS7_EncryptionAtRest()** (15 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **TestR7_EncryptionAtRest()** (13 connections) — `test/e2e/rclone/scenarios_atrest_test.go`
- **AssertStoredIsNotPlaintext()** (10 connections) — `test/e2e/harness/atrest.go`
- **MD5File()** (7 connections) — `test/e2e/harness/hash.go`
- **harness/hash.go** (6 connections) — `test/e2e/harness/hash.go`
- **storedFormat()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **atrest.go** (4 connections) — `test/e2e/harness/atrest.go`
- **Format** (4 connections) — `test/e2e/harness/atrest.go`
- **MD5Base64File()** (4 connections) — `test/e2e/harness/hash.go`
- **storedByKey()** (4 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **CopyFile()** (3 connections) — `test/e2e/harness/hash.go`
- **UserMetadata()** (3 connections) — `test/e2e/harness/stored.go`
- **statSize()** (2 connections) — `test/e2e/harness/atrest.go`
- **s3cmd/scenarios_atrest_test.go** (2 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **rclone/scenarios_atrest_test.go** (1 connections) — `test/e2e/rclone/scenarios_atrest_test.go`

## Relationships

- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (9 shared connections)
- [Stored](Stored.md) (8 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (8 shared connections)
- [rclone E2E Suite](rclone_E2E_Suite.md) (7 shared connections)
- [Scenarios Read](Scenarios_Read.md) (4 shared connections)
- [Harness](Harness.md) (3 shared connections)
- [Backend](Backend.md) (2 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (1 shared connections)

## Source Files

- `test/e2e/harness/atrest.go`
- `test/e2e/harness/hash.go`
- `test/e2e/harness/stored.go`
- `test/e2e/rclone/scenarios_atrest_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_atrest_test.go`

## Audit Trail

- EXTRACTED: 50 (79%)
- INFERRED: 13 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*