# Request: Checksum

> 14 nodes · cohesion 0.19

## Key Concepts

- **newCRC64NVME()** (6 connections) — `internal/proxy/request/crc64nvme.go`
- **checksumReader** (6 connections) — `internal/proxy/request/checksum.go`
- **BenchmarkChkCRC64NVME()** (5 connections) — `internal/proxy/request/checksum_test.go`
- **declaration** (5 connections) — `internal/proxy/request/checksum.go`
- **hash.Hash** (4 connections)
- **decodeDigest()** (4 connections) — `internal/proxy/request/checksum.go`
- **checksumAlgorithm** (4 connections) — `internal/proxy/request/checksum.go`
- **.finish()** (4 connections) — `internal/proxy/request/checksum.go`
- **TestChkCRC64NVMEAllocatesNothingPerWrite()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkCRC64NVMECheckValue()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **naiveCRC64NVME()** (3 connections) — `internal/proxy/request/crc64nvme.go`
- **mismatch()** (2 connections) — `internal/proxy/request/checksum.go`
- **.Read()** (2 connections) — `internal/proxy/request/checksum.go`
- **.Verdict()** (2 connections) — `internal/proxy/request/checksum.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (11 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum.go`
- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/crc64nvme.go`

## Audit Trail

- EXTRACTED: 30 (83%)
- INFERRED: 6 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*