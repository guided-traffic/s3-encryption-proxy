# Envelope Encryption Coverage

> 31 nodes · cohesion 0.15

## Key Concepts

- **envelope_coverage_test.go** (25 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **New()** (21 connections) — `pkg/encryption/envelope/envelope.go`
- **EnvNewAESKEK()** (13 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvDecryptWithWrongKEK()** (8 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvEncryptDecryptRoundTrip()** (8 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvGCMMetadataIVMustNotBeReplayed()** (7 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **EnvFakeKeyEncryptor** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **EnvSHA256()** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvDecryptDataStreamErrorPaths()** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvFingerprintTracksKeyEncryptor()** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvRotateKEKDelegatesToKeyEncryptor()** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvStreamingIsLazyForCTR()** (6 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **EnvMask()** (5 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvEncryptedDEKMatchesMetadataForPassThroughKEK()** (5 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvGCMTamperingIsDetected()** (5 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvMetadataPrefixIsApplied()** (5 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.Fingerprint()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **EnvDigest()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **EnvRandomBytes()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvDecryptZeroesUnwrappedDEK()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvIVMetadataHandling()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **TestEnvNewWiresProvidersAndAccessors()** (4 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- **.RotateKEK()** (3 connections) — `pkg/encryption/envelope/envelope_coverage_test.go`
- *... and 6 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (19 shared connections)
- [AES-GCM Encryption Tests](AES-GCM_Encryption_Tests.md) (7 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (4 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (3 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (2 shared connections)
- [AES KEK Provider Tests](AES_KEK_Provider_Tests.md) (1 shared connections)
- [None Provider Pass-Through](None_Provider_Pass-Through.md) (1 shared connections)

## Source Files

- `pkg/encryption/envelope/envelope.go`
- `pkg/encryption/envelope/envelope_coverage_test.go`

## Audit Trail

- EXTRACTED: 98 (86%)
- INFERRED: 16 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*