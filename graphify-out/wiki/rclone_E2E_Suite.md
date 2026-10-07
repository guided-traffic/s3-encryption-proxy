# rclone E2E Suite

> 34 nodes · cohesion 0.15

## Key Concepts

- **rclone_test.go** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **newSuite()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **preflight()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **endpoints()** (14 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR7_EncryptionAtRest()** (13 connections) — `test/e2e/rclone/scenarios_atrest_test.go`
- **TestR6_Lifecycle()** (12 connections) — `test/e2e/rclone/scenarios_lifecycle_test.go`
- **seedCorpus()** (11 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **TestR1_SinglePartUpload()** (11 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **TestR5_ReportedHashes()** (9 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **TestR4_CheckAndSync()** (9 connections) — `test/e2e/rclone/scenarios_sync_test.go`
- **TestR2_MultipartUpload()** (9 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **TestPreflight()** (8 connections) — `test/e2e/rclone/rclone_test.go`
- **remoteName()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **writeConfig()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR3_Download()** (7 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **TestR1b_EntityTagIsNotAContentDigest()** (7 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **SHA256Bytes()** (6 connections) — `test/e2e/harness/hash.go`
- **rcloneBin()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **storedFormat()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **hashsum()** (6 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **suite** (5 connections) — `test/e2e/rclone/rclone_test.go`
- **rclone/scenarios_read_test.go** (5 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **endpoint** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.remotePath()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **remote** (3 connections) — `test/e2e/rclone/rclone_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (17 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (11 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (10 shared connections)
- [E2E At-Rest Assertions](E2E_At-Rest_Assertions.md) (9 shared connections)
- [E2E Harness Environment](E2E_Harness_Environment.md) (7 shared connections)
- [Exec](Exec.md) (5 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Rclone](Rclone.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)

## Source Files

- `test/e2e/harness/hash.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/rclone/scenarios_atrest_test.go`
- `test/e2e/rclone/scenarios_lifecycle_test.go`
- `test/e2e/rclone/scenarios_read_test.go`
- `test/e2e/rclone/scenarios_sync_test.go`
- `test/e2e/rclone/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 118 (79%)
- INFERRED: 32 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*