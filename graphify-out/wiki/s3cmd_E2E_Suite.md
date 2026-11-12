# s3cmd E2E Suite

> 26 nodes · cohesion 0.14

## Key Concepts

- **s3cmd_test.go** (32 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **newSuite()** (14 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **preflight()** (12 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **seedCorpus()** (11 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **endpoints()** (10 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestS5_ReportedDigests()** (10 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **TestS4_Sync()** (9 connections) — `test/e2e/s3cmd/scenarios_sync_test.go`
- **writeConfig()** (7 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestS3_Get()** (7 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **suite** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestPreflight()** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **endpoint** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **Binary()** (5 connections) — `test/e2e/harness/harness.go`
- **s3cmdBin()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestMain()** (4 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **corpus** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **boolWord()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **reportDir()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **stripScheme()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **uniqueBucket()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **lineFor()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **oneField()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **reported()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **.uri()** (1 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **containsStr()** (1 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (24 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (11 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (10 shared connections)
- [Harness: Backend](Harness-_Backend.md) (7 shared connections)
- [Harness: Exec](Harness-_Exec.md) (5 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (3 shared connections)
- [Misc (15)](Misc_15.md) (3 shared connections)
- [Harness: Harness](Harness-_Harness.md) (2 shared connections)
- [Rclone: Rclone Test (2)](Rclone-_Rclone_Test_2.md) (2 shared connections)
- [Harness: Verdict](Harness-_Verdict.md) (1 shared connections)

## Source Files

- `test/e2e/harness/harness.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_read_test.go`
- `test/e2e/s3cmd/scenarios_sync_test.go`

## Audit Trail

- EXTRACTED: 102 (89%)
- INFERRED: 13 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*