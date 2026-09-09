# Streaming IO Reader Tests

> 42 nodes · cohesion 0.21

## Key Concepts

- **streaming_io_coverage_test.go** (43 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrPayload()** (27 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrCTR()** (19 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrReadAll()** (18 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrSHA256()** (18 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrHMACManager()** (15 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrLogger()** (15 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrDEK()** (14 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **newHMACGatedDecryptionReader()** (13 connections) — `internal/orchestration/streaming_io.go`
- **.Read()** (13 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrGatedFixture()** (12 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrNewHVR()** (12 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderRoundTrip()** (12 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderCalculatorFailure()** (10 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderPropagatesSourceError()** (10 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderWithholdsFinalChunkOnTamper()** (10 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACGatedReaderWithoutHMAC()** (9 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACValidatingReaderHoldsBackDataEOFChunk()** (9 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACValidatingReaderCalculatorFailure()** (8 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACValidatingReaderPropagatesSourceError()** (8 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrHMACValidatingReaderWithoutExpectedHMAC()** (8 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **.Close()** (8 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **OrcStrExpectedHMAC()** (7 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrEncryptionReaderBoundarySizes()** (7 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- **TestOrcStrEncryptionReaderDataWithEOFInSameRead()** (7 connections) — `internal/orchestration/streaming_io_coverage_test.go`
- *... and 17 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (30 shared connections)
- [Range Decryption Reader Tests](Range_Decryption_Reader_Tests.md) (15 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (6 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (5 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (4 shared connections)
- [Chunk Reader Test Fake](Chunk_Reader_Test_Fake.md) (1 shared connections)
- [EOF Reader Test Fake](EOF_Reader_Test_Fake.md) (1 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (1 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)

## Source Files

- `internal/orchestration/streaming_io.go`
- `internal/orchestration/streaming_io_coverage_test.go`

## Audit Trail

- EXTRACTED: 226 (92%)
- INFERRED: 19 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*