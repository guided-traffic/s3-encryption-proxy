# s3cmd E2E Suite

> 27 nodes · cohesion 0.19

## Key Concepts

- **s3cmd_test.go** (32 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **newSuite()** (17 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **preflight()** (16 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **endpoints()** (14 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **WriteRandomFile()** (13 connections) — `test/e2e/harness/hash.go`
- **TestS6_Lifecycle()** (12 connections) — `test/e2e/s3cmd/scenarios_lifecycle_test.go`
- **TestS1_SinglePartPut()** (11 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **SHA256File()** (10 connections) — `test/e2e/harness/hash.go`
- **TestS5_ReportedDigests()** (10 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **TestS2_MultipartPut()** (10 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **TestS2b_ProducerObject()** (10 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **TestS4_Sync()** (9 connections) — `test/e2e/s3cmd/scenarios_sync_test.go`
- **writeConfig()** (8 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestS3_Get()** (7 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **suite** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **s3cmdBin()** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestPreflight()** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **endpoint** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **CopyFile()** (3 connections) — `test/e2e/harness/hash.go`
- **uniqueBucket()** (3 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **lineFor()** (3 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **boolWord()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **containsStr()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **stripScheme()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **oneField()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- *... and 2 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (28 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (17 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (16 shared connections)
- [Harness: Backend](Harness-_Backend.md) (11 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (7 shared connections)
- [Harness: Exec](Harness-_Exec.md) (6 shared connections)
- [Rclone: Rclone Test (2)](Rclone-_Rclone_Test_2.md) (2 shared connections)
- [Tampering Harness](Tampering_Harness.md) (2 shared connections)
- [Rclone: Scenarios Read Test](Rclone-_Scenarios_Read_Test.md) (1 shared connections)
- [Harness: Verdict](Harness-_Verdict.md) (1 shared connections)
- [Harness: Harness](Harness-_Harness.md) (1 shared connections)

## Source Files

- `test/e2e/harness/hash.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_lifecycle_test.go`
- `test/e2e/s3cmd/scenarios_read_test.go`
- `test/e2e/s3cmd/scenarios_sync_test.go`
- `test/e2e/s3cmd/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 128 (82%)
- INFERRED: 29 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*