# E2E Harness Environment

> 9 nodes · cohesion 0.47

## Key Concepts

- **DemoStack()** (16 connections) — `test/e2e/harness/harness.go`
- **CACert()** (8 connections) — `test/e2e/harness/harness.go`
- **LoadEnv()** (7 connections) — `test/e2e/harness/harness.go`
- **harness/harness.go** (6 connections) — `test/e2e/harness/harness.go`
- **Env** (5 connections) — `test/e2e/harness/harness.go`
- **Binary()** (5 connections) — `test/e2e/harness/harness.go`
- **RepoRoot()** (5 connections) — `test/e2e/harness/harness.go`
- **.Get()** (4 connections) — `test/e2e/harness/harness.go`
- **.GetInt()** (3 connections) — `test/e2e/harness/harness.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [rclone E2E Suite](rclone_E2E_Suite.md) (7 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (5 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (3 shared connections)
- [E2E At-Rest Assertions](E2E_At-Rest_Assertions.md) (2 shared connections)
- [Exec](Exec.md) (1 shared connections)

## Source Files

- `test/e2e/harness/harness.go`

## Audit Trail

- EXTRACTED: 39 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*