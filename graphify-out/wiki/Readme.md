# Readme

> 13 nodes · cohesion 0.21

## Key Concepts

- **Local Performance Baseline Suite** (10 connections) — `test/perf/README.md`
- **TestUnwrapMicrobenchmark()** (8 connections) — `test/perf/unwrap_test.go`
- **median()** (6 connections) — `test/perf/unwrap_test.go`
- **Memory Bound (ADR 0020 D14) — the One Assertion** (4 connections) — `test/perf/README.md`
- **memory Instrument (RSS and Profiles)** (4 connections) — `test/perf/README.md`
- **unwrap_test.go** (4 connections) — `test/perf/unwrap_test.go`
- **smallobject Instrument** (3 connections) — `test/perf/README.md`
- **Resident Memory Fell — 130 MB to 109 MB Peak** (2 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Instruments Record, They Do Not Assert** (2 connections) — `test/perf/README.md`
- **unwrap Instrument (KEK Wrap/Unwrap)** (2 connections) — `test/perf/README.md`
- **rsaName()** (2 connections) — `test/perf/unwrap_test.go`
- **HeadBucket Answered 200 for a Missing Bucket** (1 connections) — `test/perf/README.md`
- **perf Build Tag — Local by Design** (1 connections) — `test/perf/README.md`

## Relationships

- [Performance Test Client](Performance_Test_Client.md) (4 shared connections)
- [Performance Baselines and Findings](Performance_Baselines_and_Findings.md) (3 shared connections)
- [Throughput](Throughput.md) (2 shared connections)
- [Smallobject](Smallobject.md) (2 shared connections)
- [Harness](Harness.md) (2 shared connections)
- [Values Proxy](Values_Proxy.md) (1 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)

## Source Files

- `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- `test/perf/README.md`
- `test/perf/unwrap_test.go`

## Audit Trail

- EXTRACTED: 25 (76%)
- INFERRED: 8 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*