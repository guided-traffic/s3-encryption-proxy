# AES-CTR Data Encryption Tests

> 36 nodes · cohesion 0.14

## Key Concepts

- **aes_ctr_coverage_test.go** (30 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **DekrandomBytes()** (28 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **NewAESCTRDataEncryptor()** (23 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **Deksum()** (11 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **NewAESCTRStatefulEncryptor()** (11 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **DekencryptCTR()** (8 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRRoundTripSizes()** (8 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRStatefulEncryptorRoundTrip()** (8 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **NewAESCTRStatefulEncryptorWithIV()** (8 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **TestDekAESCTRWrongKeyOrIVYieldsGarbageWithoutError()** (7 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **DekbreakRandReader()** (6 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRDecryptStreamValidation()** (6 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTREncryptStreamEntropyFailure()** (6 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekCTRStreamAtMatchesStatefulEncryptor()** (6 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **Deksize()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTREncryptStreamRejectsBadDEK()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRFreshIVPerEncryption()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRGetLastIV()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRStatefulConstructorValidation()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRStatefulEncryptorEntropyFailure()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRStatefulEncryptPartIsInPlace()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekNewCTRRangeReaderPastEndOfObject()** (5 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **Dekitoa()** (4 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRGenerateDEKEntropyFailure()** (4 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **TestDekAESCTRStatefulCleanupWipesKeyMaterial()** (4 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- *... and 11 more nodes in this community*

## Relationships

- [AES-GCM Encryption Tests](AES-GCM_Encryption_Tests.md) (26 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (24 shared connections)
- [AES-CTR Range Reader](AES-CTR_Range_Reader.md) (8 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (4 shared connections)
- [Streaming SHA-256 Test Util](Streaming_SHA-256_Test_Util.md) (2 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (2 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (2 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (2 shared connections)
- [Ciphertext Size Arithmetic](Ciphertext_Size_Arithmetic.md) (1 shared connections)
- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/aes_ctr.go`
- `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- `pkg/encryption/dataencryption/aes_ctr_test.go`

## Audit Trail

- EXTRACTED: 116 (72%)
- INFERRED: 45 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*