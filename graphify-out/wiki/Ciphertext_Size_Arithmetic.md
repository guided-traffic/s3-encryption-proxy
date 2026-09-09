# Ciphertext Size Arithmetic

> 14 nodes · cohesion 0.26

## Key Concepts

- **ComputePlaintextSize()** (10 connections) — `pkg/encryption/ciphertext_size.go`
- **ComputeCiphertextSize()** (9 connections) — `pkg/encryption/ciphertext_size.go`
- **TestComputeCiphertextSizeMatchesTheRealEncryptors()** (7 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **ciphertext_size_invariant_test.go** (6 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **encryptAll()** (5 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **TestComputeSizesRejectUnknownAlgorithms()** (4 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **TestGCMOverheadIsNonceAndTag()** (4 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **TestPassthroughAlgorithmsAddNothing()** (4 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **TestComputePlaintextSize_InvertsComputeCiphertextSize()** (4 connections) — `pkg/encryption/ciphertext_size_test.go`
- **TestComputePlaintextSizeRejectsShortGCMObjects()** (3 connections) — `pkg/encryption/ciphertext_size_invariant_test.go`
- **ciphertext_size_test.go** (3 connections) — `pkg/encryption/ciphertext_size_test.go`
- **TestComputeCiphertextSize()** (3 connections) — `pkg/encryption/ciphertext_size_test.go`
- **TestComputePlaintextSize_EdgeCases()** (3 connections) — `pkg/encryption/ciphertext_size_test.go`
- **ciphertext_size.go** (2 connections) — `pkg/encryption/ciphertext_size.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (9 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [AES-GCM Encryption Tests](AES-GCM_Encryption_Tests.md) (2 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (1 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/ciphertext_size.go`
- `pkg/encryption/ciphertext_size_invariant_test.go`
- `pkg/encryption/ciphertext_size_test.go`

## Audit Trail

- EXTRACTED: 39 (91%)
- INFERRED: 4 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*