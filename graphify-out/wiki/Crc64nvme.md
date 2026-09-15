# Crc64nvme

> 14 nodes · cohesion 0.16

## Key Concepts

- **crc64NVME** (6 connections) — `internal/proxy/request/crc64nvme.go`
- **crc64nvme.go** (5 connections) — `internal/proxy/request/crc64nvme.go`
- **newCRC64NVME()** (5 connections) — `internal/proxy/request/crc64nvme.go`
- **BenchmarkChkCRC64NVME()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkCRC64NVMEAllocatesNothingPerWrite()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkCRC64NVMECheckValue()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **naiveCRC64NVME()** (3 connections) — `internal/proxy/request/crc64nvme.go`
- **crc64NVMEUpdate()** (2 connections) — `internal/proxy/request/crc64nvme.go`
- **.Write()** (2 connections) — `internal/proxy/request/crc64nvme.go`
- **makeCRC64SlicingBy8()** (1 connections) — `internal/proxy/request/crc64nvme.go`
- **.BlockSize()** (1 connections) — `internal/proxy/request/crc64nvme.go`
- **.Reset()** (1 connections) — `internal/proxy/request/crc64nvme.go`
- **.Size()** (1 connections) — `internal/proxy/request/crc64nvme.go`
- **.Sum()** (1 connections) — `internal/proxy/request/crc64nvme.go`

## Relationships

- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (3 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (2 shared connections)
- [Checksum](Checksum.md) (2 shared connections)
- [Performance](Performance.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/crc64nvme.go`

## Audit Trail

- EXTRACTED: 19 (83%)
- INFERRED: 4 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*