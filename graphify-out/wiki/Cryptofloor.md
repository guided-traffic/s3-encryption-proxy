# Cryptofloor

> 11 nodes · cohesion 0.24

## Key Concepts

- **TestCryptoFloor()** (9 connections) — `test/perf/cryptofloor_test.go`
- **cryptofloor Instrument (In-Process Crypto Floor)** (5 connections) — `test/perf/README.md`
- **crypto/cipher.AEAD** (4 connections)
- **cryptofloor_test.go** (4 connections) — `test/perf/cryptofloor_test.go`
- **openSegments()** (3 connections) — `test/perf/cryptofloor_test.go`
- **sealSegments()** (3 connections) — `test/perf/cryptofloor_test.go`
- **emptyDir Data Volume — the Backend Must Not Depend on the Thing Under Test** (2 connections) — `test/e2e/velero/manifests/minio.yaml`
- **Every Variant Must Allocate the Same** (2 connections) — `test/perf/README.md`
- **Noise Floor — Below 10 % Is the Machine** (2 connections) — `test/perf/README.md`
- **64 KiB Is Where the Instrument Stops Resolving** (1 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- **Downloads and the Crypto Floor Are Unchanged** (1 connections) — `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`

## Relationships

- [Harness](Harness.md) (2 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (1 shared connections)
- [Values Proxy](Values_Proxy.md) (1 shared connections)
- [Segmented GCM Vector](Segmented_GCM_Vector.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)
- [Report](Report.md) (1 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)
- [Readme](Readme.md) (1 shared connections)

## Source Files

- `perf-baseline/20260911T103132Z-cc62c05/FINDINGS.md`
- `test/e2e/velero/manifests/minio.yaml`
- `test/perf/README.md`
- `test/perf/cryptofloor_test.go`

## Audit Trail

- EXTRACTED: 18 (78%)
- INFERRED: 5 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*