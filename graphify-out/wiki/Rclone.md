# Rclone

> 7 nodes · cohesion 0.33

## Key Concepts

- **testing.M** (4 connections)
- **TestMain()** (4 connections) — `test/e2e/rclone/rclone_test.go`
- **TestMain()** (4 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **WriteStepSummary()** (3 connections) — `test/e2e/harness/verdict.go`
- **reportDir()** (2 connections) — `test/e2e/rclone/rclone_test.go`
- **reportDir()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestMain()** (2 connections) — `test/e2e/velero/e2e_test.go`

## Relationships

- [rclone E2E Suite](rclone_E2E_Suite.md) (2 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (2 shared connections)
- [Main](Main.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (1 shared connections)

## Source Files

- `test/e2e/harness/verdict.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/velero/e2e_test.go`

## Audit Trail

- EXTRACTED: 14 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*