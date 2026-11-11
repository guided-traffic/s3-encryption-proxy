# Rclone: Rclone Test

> 20 nodes · cohesion 0.27

## Key Concepts

- **rclone_test.go** (32 connections) — `test/e2e/rclone/rclone_test.go`
- **newSuite()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **preflight()** (16 connections) — `test/e2e/rclone/rclone_test.go`
- **endpoints()** (14 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR6_Lifecycle()** (12 connections) — `test/e2e/rclone/scenarios_lifecycle_test.go`
- **TestR1_SinglePartUpload()** (11 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **TestR4_CheckAndSync()** (9 connections) — `test/e2e/rclone/scenarios_sync_test.go`
- **TestR2_MultipartUpload()** (9 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **remoteName()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **TestPreflight()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **writeConfig()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **TestR3_Download()** (7 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **TestR1b_EntityTagIsNotAContentDigest()** (7 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **rcloneBin()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **suite** (5 connections) — `test/e2e/rclone/rclone_test.go`
- **endpoint** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.remotePath()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **remote** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **uniqueBucket()** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **ptr()** (1 connections) — `test/e2e/rclone/rclone_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (21 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (12 shared connections)
- [Harness: Backend](Harness-_Backend.md) (10 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (7 shared connections)
- [Harness: Exec](Harness-_Exec.md) (5 shared connections)
- [Rclone: Scenarios Read Test](Rclone-_Scenarios_Read_Test.md) (5 shared connections)
- [Rclone: Rclone Test (2)](Rclone-_Rclone_Test_2.md) (2 shared connections)
- [Tampering Harness](Tampering_Harness.md) (2 shared connections)
- [Harness: Verdict](Harness-_Verdict.md) (1 shared connections)
- [Harness: Harness](Harness-_Harness.md) (1 shared connections)

## Source Files

- `test/e2e/rclone/rclone_test.go`
- `test/e2e/rclone/scenarios_lifecycle_test.go`
- `test/e2e/rclone/scenarios_read_test.go`
- `test/e2e/rclone/scenarios_sync_test.go`
- `test/e2e/rclone/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 100 (78%)
- INFERRED: 29 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*