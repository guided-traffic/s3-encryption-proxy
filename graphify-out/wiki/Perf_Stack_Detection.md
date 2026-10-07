# Perf Stack Detection

> 5 nodes · cohesion 0.70

## Key Concepts

- **perf/main_test.go** (5 connections) — `test/perf/main_test.go`
- **detectStack()** (5 connections) — `test/perf/main_test.go`
- **insecureClient()** (4 connections) — `test/perf/main_test.go`
- **reachable()** (3 connections) — `test/perf/main_test.go`
- **readProxyConfig()** (2 connections) — `test/perf/main_test.go`

## Relationships

- [Harness](Harness.md) (3 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (2 shared connections)

## Source Files

- `test/perf/main_test.go`

## Audit Trail

- EXTRACTED: 11 (92%)
- INFERRED: 1 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*