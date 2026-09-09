# Range Decryption Reader Tests

> 14 nodes · cohesion 0.34

## Key Concepts

- **OrcStrNewManager()** (13 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **OrcStrAESConfig()** (11 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **orchestration/rangeread_coverage_test.go** (10 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **OrcStrEncryptCTR()** (8 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrCreateRangeDecryptionReaderIsChunkSizeIndependent()** (8 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrCreateRangeDecryptionReaderMatchesPlaintextSlice()** (7 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrRangedReadIsNotIntegrityChecked()** (7 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrCreateRangeDecryptionReaderErrors()** (6 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrCreateRangeDecryptionReaderNoneProviderPassThrough()** (6 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrCreateRangeDecryptionReaderUnsupportedIsTyped()** (4 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **TestOrcStrSupportsRangeDecryption()** (4 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **Manager** (2 connections)
- **TestOrcStrRangeReadUnsupportedErrorMessage()** (2 connections) — `internal/orchestration/rangeread_coverage_test.go`
- **OrcStrPrefixPtr()** (2 connections) — `internal/orchestration/streaming_io_coverage_test.go`

## Relationships

- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (15 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (10 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/rangeread_coverage_test.go`
- `internal/orchestration/streaming_io_coverage_test.go`

## Audit Trail

- EXTRACTED: 39 (66%)
- INFERRED: 20 (34%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*