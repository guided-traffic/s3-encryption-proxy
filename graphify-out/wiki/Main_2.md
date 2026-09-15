# Main

> 8 nodes · cohesion 0.43

## Key Concepts

- **TestMain()** (6 connections) — `test/perf/main_test.go`
- **perf/main_test.go** (5 connections) — `test/perf/main_test.go`
- **detectStack()** (5 connections) — `test/perf/main_test.go`
- **StackInfo** (4 connections) — `test/perf/harness.go`
- **insecureClient()** (4 connections) — `test/perf/main_test.go`
- **SetStack()** (3 connections) — `test/perf/harness.go`
- **reachable()** (3 connections) — `test/perf/main_test.go`
- **readProxyConfig()** (2 connections) — `test/perf/main_test.go`

## Relationships

- [Harness](Harness.md) (4 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (2 shared connections)
- [Report](Report.md) (1 shared connections)
- [Rclone](Rclone.md) (1 shared connections)

## Source Files

- `test/perf/harness.go`
- `test/perf/main_test.go`

## Audit Trail

- EXTRACTED: 16 (80%)
- INFERRED: 4 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*