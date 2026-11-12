# Rclone: Rclone Test (2)

> 5 nodes · cohesion 0.40

## Key Concepts

- **testing.M** (4 connections)
- **TestMain()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **WriteStepSummary()** (3 connections) — `test/e2e/harness/verdict.go`
- **reportDir()** (2 connections) — `test/e2e/rclone/rclone_test.go`
- **TestMain()** (2 connections) — `test/e2e/velero/e2e_test.go`

## Relationships

- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (2 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (2 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/e2e/harness/verdict.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/velero/e2e_test.go`

## Audit Trail

- EXTRACTED: 11 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*