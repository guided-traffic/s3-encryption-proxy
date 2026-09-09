# AES-CTR Range Reader

> 18 nodes · cohesion 0.16

## Key Concepts

- **aes_ctr.go** (9 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **NewCTRRangeReader()** (8 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **NewCTRStreamAt()** (6 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **aes_ctr_range_test.go** (6 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **TestNewCTRRangeReader_MatchesFullDecryption()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **TestNewCTRStreamAt_ZeroOffsetEqualsPlainCTR()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **ctrStreamReader** (4 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.CreateRangeDecryptionReader()** (4 connections) — `internal/orchestration/rangeread.go`
- **addCounter()** (4 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **crypto/cipher.Stream** (3 connections)
- **Manager** (3 connections) — `internal/orchestration/rangeread.go`
- **TestDekNewCTRRangeReaderRejectsBadKeyMaterial()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestAddCounter()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **TestAddCounter_DoesNotMutateInput()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **TestNewCTRStreamAt_Validation()** (3 connections) — `pkg/encryption/dataencryption/aes_ctr_range_test.go`
- **.Read()** (1 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **.GetMetadataAlgorithm()** (1 connections) — `internal/orchestration/rangeread.go`
- **.SupportsRangeDecryption()** (1 connections) — `internal/orchestration/rangeread.go`

## Relationships

- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (8 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (6 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (2 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (1 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (1 shared connections)

## Source Files

- `internal/orchestration/rangeread.go`
- `pkg/encryption/dataencryption/aes_ctr.go`
- `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- `pkg/encryption/dataencryption/aes_ctr_range_test.go`

## Audit Trail

- EXTRACTED: 38 (79%)
- INFERRED: 10 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*