# Exec

> 19 nodes · cohesion 0.19

## Key Concepts

- **Result** (12 connections) — `test/e2e/harness/exec.go`
- **harness/exec.go** (8 connections) — `test/e2e/harness/exec.go`
- **.run()** (7 connections) — `test/e2e/rclone/rclone_test.go`
- **MustRun()** (7 connections) — `test/e2e/harness/exec.go`
- **Run()** (7 connections) — `test/e2e/harness/exec.go`
- **RunWithEnv()** (7 connections) — `test/e2e/harness/exec.go`
- **bytes.Buffer** (6 connections)
- **teeBuffer** (4 connections) — `test/e2e/harness/exec.go`
- **.says()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.says()** (4 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **io2()** (4 connections) — `test/e2e/harness/exec.go`
- **Redact()** (3 connections) — `test/e2e/harness/exec.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **.Command()** (2 connections) — `test/e2e/harness/exec.go`
- **.OK()** (2 connections) — `test/e2e/harness/exec.go`
- **FirstMatch()** (2 connections) — `test/e2e/harness/exec.go`
- **regexp.Regexp** (1 connections)
- **.Write()** (1 connections) — `test/e2e/harness/exec.go`

## Relationships

- [rclone E2E Suite](rclone_E2E_Suite.md) (5 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (5 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)
- [S3 Error Document Writer](S3_Error_Document_Writer.md) (2 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (2 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (1 shared connections)
- [Harness](Harness.md) (1 shared connections)

## Source Files

- `test/e2e/harness/exec.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`

## Audit Trail

- EXTRACTED: 54 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*