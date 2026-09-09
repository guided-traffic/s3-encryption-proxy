# Encryption Factory Tests

> 25 nodes · cohesion 0.22

## Key Concepts

- **factory_coverage_test.go** (20 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.Fingerprint()** (14 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **NewFactory()** (14 connections) — `pkg/encryption/factory/factory.go`
- **FacFactoryWithAES()** (12 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (9 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacReadAll()** (8 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacEnvelopeWithRSAKEKRoundTrip()** (7 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacStubKeyEncryptor** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateEnvelopeEncryptorRoundTrip()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacEnvelopeWithNoneKEKStillEncryptsData()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacEnvelopeWrongKEKCannotRecoverPlaintext()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacDigest()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacRSAKeyPairPEM()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacContentTypeSelectsMatchingDataEncryptor()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateEnvelopeEncryptorUnknownFingerprint()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacEnvelopeGCMDetectsTampering()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetRegisteredProviderInfo()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.Name()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateAESKeyEncryptorKEKPathMatchesBase64Path()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateEnvelopeEncryptorMetadataPrefixIsHonoured()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacRegisterKeyEncryptorKeysByFingerprint()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.RotateKEK()** (2 connections) — `pkg/encryption/factory/factory_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (16 shared connections)
- [Content Type Factory Selection](Content_Type_Factory_Selection.md) (10 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (3 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (1 shared connections)

## Source Files

- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`

## Audit Trail

- EXTRACTED: 87 (86%)
- INFERRED: 14 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*