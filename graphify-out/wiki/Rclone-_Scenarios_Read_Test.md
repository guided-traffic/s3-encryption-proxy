# Rclone: Scenarios Read Test

> 6 nodes · cohesion 0.47

## Key Concepts

- **seedCorpus()** (11 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **TestR5_ReportedHashes()** (9 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **hashsum()** (6 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **endpoint** (2 connections)
- **corpus** (2 connections) — `test/e2e/rclone/scenarios_read_test.go`
- **suite** (2 connections)

## Relationships

- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (5 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (3 shared connections)
- [Tampering Harness](Tampering_Harness.md) (2 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/e2e/rclone/scenarios_read_test.go`

## Audit Trail

- EXTRACTED: 20 (80%)
- INFERRED: 5 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*