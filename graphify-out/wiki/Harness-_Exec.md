# Harness: Exec

> 16 nodes · cohesion 0.18

## Key Concepts

- **Result** (12 connections) — `test/e2e/harness/exec.go`
- **Run()** (7 connections) — `test/e2e/harness/exec.go`
- **RunWithEnv()** (7 connections) — `test/e2e/harness/exec.go`
- **CACert()** (7 connections) — `test/e2e/harness/harness.go`
- **.run()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **.run()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **MustRun()** (5 connections) — `test/e2e/harness/exec.go`
- **Binary()** (5 connections) — `test/e2e/harness/harness.go`
- **RepoRoot()** (5 connections) — `test/e2e/harness/harness.go`
- **.says()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **.says()** (4 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **Redact()** (3 connections) — `test/e2e/harness/exec.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/rclone/rclone_test.go`
- **pickVerdictLine()** (3 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **.Command()** (1 connections) — `test/e2e/harness/exec.go`
- **.OK()** (1 connections) — `test/e2e/harness/exec.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (6 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (6 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (5 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (1 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (1 shared connections)
- [Harness: Backend](Harness-_Backend.md) (1 shared connections)
- [Harness: Harness](Harness-_Harness.md) (1 shared connections)

## Source Files

- `test/e2e/harness/exec.go`
- `test/e2e/harness/harness.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`

## Audit Trail

- EXTRACTED: 55 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*