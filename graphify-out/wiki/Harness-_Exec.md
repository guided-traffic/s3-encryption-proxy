# Harness: Exec

> 14 nodes · cohesion 0.22

## Key Concepts

- **Result** (12 connections) — `test/e2e/harness/exec.go`
- **Run()** (7 connections) — `test/e2e/harness/exec.go`
- **RunWithEnv()** (7 connections) — `test/e2e/harness/exec.go`
- **CACert()** (7 connections) — `test/e2e/harness/harness.go`
- **.run()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **.run()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **MustRun()** (5 connections) — `test/e2e/harness/exec.go`
- **.says()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.says()** (4 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **Redact()** (3 connections) — `test/e2e/harness/exec.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **.Command()** (1 connections) — `test/e2e/harness/exec.go`
- **.OK()** (1 connections) — `test/e2e/harness/exec.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (6 shared connections)
- [Misc (15)](Misc_15.md) (5 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (5 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (4 shared connections)
- [Keyencryption: Aes Test](Keyencryption-_Aes_Test.md) (1 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (1 shared connections)
- [Harness: Harness](Harness-_Harness.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)

## Source Files

- `test/e2e/harness/exec.go`
- `test/e2e/harness/harness.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`

## Audit Trail

- EXTRACTED: 47 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*