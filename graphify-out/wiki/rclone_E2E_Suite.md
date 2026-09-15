# rclone E2E Suite

> 24 nodes · cohesion 0.21

## Key Concepts

- **rclone_test.go** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **newSuite()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **preflight()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **endpoints()** (14 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR6_Lifecycle()** (12 connections) — `test/e2e/rclone/scenarios_lifecycle_test.go`
- **TestR1_SinglePartUpload()** (11 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **TestR4_CheckAndSync()** (9 connections) — `test/e2e/rclone/scenarios_sync_test.go`
- **TestR2_MultipartUpload()** (9 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **TestPreflight()** (8 connections) — `test/e2e/rclone/rclone_test.go`
- **remoteName()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **writeConfig()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR1b_EntityTagIsNotAContentDigest()** (7 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **SHA256Bytes()** (6 connections) — `test/e2e/harness/hash.go`
- **rcloneBin()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **storedFormat()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **suite** (5 connections) — `test/e2e/rclone/rclone_test.go`
- **endpoint** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.remotePath()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **remote** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **uniqueBucket()** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **rclone/scenarios_upload_test.go** (3 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **ptr()** (1 connections) — `test/e2e/rclone/rclone_test.go`
- **rclone/scenarios_lifecycle_test.go** (1 connections) — `test/e2e/rclone/scenarios_lifecycle_test.go`
- **rclone/scenarios_sync_test.go** (1 connections) — `test/e2e/rclone/scenarios_sync_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (12 shared connections)
- [Backend](Backend.md) (10 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (8 shared connections)
- [Scenarios Atrest](Scenarios_Atrest.md) (7 shared connections)
- [Scenarios Read](Scenarios_Read.md) (7 shared connections)
- [Exec](Exec.md) (5 shared connections)
- [Harness](Harness.md) (5 shared connections)
- [Stored](Stored.md) (3 shared connections)
- [Rclone](Rclone.md) (2 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (2 shared connections)

## Source Files

- `test/e2e/harness/hash.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/rclone/scenarios_lifecycle_test.go`
- `test/e2e/rclone/scenarios_sync_test.go`
- `test/e2e/rclone/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 87 (74%)
- INFERRED: 31 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*