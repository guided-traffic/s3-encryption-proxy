# AES-GCM Encryption Tests

> 21 nodes · cohesion 0.23

## Key Concepts

- **NewAESGCMDataEncryptor()** (27 connections) — `pkg/encryption/dataencryption/aes_gcm.go`
- **DekbufReader()** (20 connections) — `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- **aes_gcm_coverage_test.go** (14 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **DekencryptGCM()** (11 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMRoundTripSizes()** (8 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMExplicitNonceBranch()** (7 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMDetectsTampering()** (6 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMEntropyFailures()** (6 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMGenerateDEK()** (6 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMWrongKeyAndWrongAssociatedData()** (6 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMFreshNoncePerEncryption()** (5 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMGetLastIV()** (5 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMRejectsBadDEK()** (5 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMShortEncryptedData()** (5 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMDistinctEncryptorsDoNotCollide()** (4 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestDekAESGCMSourceReadErrors()** (4 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **TestAESGCMProvider_EncryptDecrypt()** (4 connections) — `pkg/encryption/dataencryption/aes_gcm_test.go`
- **TestDekAESGCMAlgorithmAndInterface()** (3 connections) — `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- **aes_gcm_test.go** (3 connections) — `pkg/encryption/dataencryption/aes_gcm_test.go`
- **TestAESGCMProvider_Algorithm()** (3 connections) — `pkg/encryption/dataencryption/aes_gcm_test.go`
- **TestAESGCMProvider_GenerateDEK()** (3 connections) — `pkg/encryption/dataencryption/aes_gcm_test.go`

## Relationships

- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (26 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (17 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (7 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (2 shared connections)
- [Ciphertext Size Arithmetic](Ciphertext_Size_Arithmetic.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (1 shared connections)
- [Streaming SHA-256 Test Util](Streaming_SHA-256_Test_Util.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/aes_ctr_coverage_test.go`
- `pkg/encryption/dataencryption/aes_gcm.go`
- `pkg/encryption/dataencryption/aes_gcm_coverage_test.go`
- `pkg/encryption/dataencryption/aes_gcm_test.go`

## Audit Trail

- EXTRACTED: 63 (59%)
- INFERRED: 43 (41%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*