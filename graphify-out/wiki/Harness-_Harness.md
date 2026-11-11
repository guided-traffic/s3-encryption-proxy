# Harness: Harness

> 4 nodes · cohesion 0.67

## Key Concepts

- **LoadEnv()** (7 connections) — `test/e2e/harness/harness.go`
- **Env** (5 connections) — `test/e2e/harness/harness.go`
- **.Get()** (3 connections) — `test/e2e/harness/harness.go`
- **.GetInt()** (3 connections) — `test/e2e/harness/harness.go`

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Harness: Exec](Harness-_Exec.md) (1 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (1 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/e2e/harness/harness.go`

## Audit Trail

- EXTRACTED: 13 (93%)
- INFERRED: 1 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*