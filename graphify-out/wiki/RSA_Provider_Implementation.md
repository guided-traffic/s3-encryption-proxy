# RSA Provider Implementation

> 16 nodes · cohesion 0.21

## Key Concepts

- **NewRSAProviderFromPEM()** (9 connections) — `pkg/encryption/keyencryption/rsa.go`
- **rsa.go** (8 connections) — `pkg/encryption/keyencryption/rsa.go`
- **crypto/rsa.PublicKey** (7 connections)
- **rsa_test.go** (7 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **NewRSAProviderFromConfig()** (6 connections) — `pkg/encryption/keyencryption/rsa.go`
- **generateTestRSAKeyPair()** (6 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **TestRSAKeyEncryptor_Algorithm()** (4 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **TestRSAKeyEncryptor_Basic()** (4 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **TestRSAKeyPairValidation()** (4 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **TestRSAKeyPairValidation_EdgeCases()** (4 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **validateRSAKeyPair()** (4 connections) — `pkg/encryption/keyencryption/rsa.go`
- **parseRSAPrivateKeyFromPEM()** (3 connections) — `pkg/encryption/keyencryption/rsa.go`
- **parseRSAPublicKeyFromPEM()** (3 connections) — `pkg/encryption/keyencryption/rsa.go`
- **TestRSAConfig()** (3 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **TestRSAProviderFromPEM()** (3 connections) — `pkg/encryption/keyencryption/rsa_test.go`
- **RSAConfig** (2 connections) — `pkg/encryption/keyencryption/rsa.go`

## Relationships

- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (15 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (3 shared connections)
- [RSA KEK Provider](RSA_KEK_Provider.md) (2 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/rsa.go`
- `pkg/encryption/keyencryption/rsa_test.go`

## Audit Trail

- EXTRACTED: 44 (85%)
- INFERRED: 8 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*