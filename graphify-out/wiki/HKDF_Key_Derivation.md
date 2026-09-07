# HKDF Key Derivation

> 31 nodes · cohesion 0.12

## Key Concepts

- **DeriveIntegrityKey()** (19 connections) — `internal/validation/hkdf.go`
- **TestValHKDFConfigDerivationProperties()** (12 connections) — `internal/validation/hkdf_coverage_test.go`
- **hkdf_test.go** (11 connections) — `internal/validation/hkdf_test.go`
- **NewHKDFConfig()** (10 connections) — `internal/validation/hkdf.go`
- **HKDFConfig** (7 connections) — `internal/validation/hkdf.go`
- **TestValDeriveIntegrityKeyPackageLevel()** (6 connections) — `internal/validation/hkdf_coverage_test.go`
- **ValderiveReference()** (6 connections) — `internal/validation/hkdf_coverage_test.go`
- **TestHKDFConfig_DeriveIntegrityKey()** (6 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_DeriveIntegrityKeyWithSalt()** (6 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_GenerateRandomSalt()** (6 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_Validate()** (6 connections) — `internal/validation/hkdf_test.go`
- **hkdf_coverage_test.go** (5 connections) — `internal/validation/hkdf_coverage_test.go`
- **.DeriveIntegrityKey()** (5 connections) — `internal/validation/hkdf.go`
- **.GenerateRandomSalt()** (5 connections) — `internal/validation/hkdf.go`
- **BenchmarkHKDFDerivation()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_DeriveIntegrityKeyWithRandomSalt()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFSecurityProperties()** (4 connections) — `internal/validation/hkdf_test.go`
- **hkdf.go** (4 connections) — `internal/validation/hkdf.go`
- **.DeriveIntegrityKeyWithRandomSalt()** (4 connections) — `internal/validation/hkdf.go`
- **.DeriveIntegrityKeyWithSalt()** (4 connections) — `internal/validation/hkdf.go`
- **TestHKDFDifferentHashAlgorithms()** (3 connections) — `internal/validation/hkdf_test.go`
- **.getHashFunction()** (3 connections) — `internal/validation/hkdf.go`
- **.Validate()** (3 connections) — `internal/validation/hkdf.go`
- **AESCTRDataEncryptor.GenerateDEK (256-bit)** (2 connections) — `pkg/encryption/dataencryption/aes_ctr.go`
- **ValFileHMACSalt (pinned wire-format salt)** (2 connections) — `internal/validation/hkdf_coverage_test.go`
- *... and 6 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `internal/validation/hkdf.go`
- `internal/validation/hkdf_coverage_test.go`
- `internal/validation/hkdf_test.go`
- `pkg/encryption/dataencryption/aes_ctr.go`

## Audit Trail

- EXTRACTED: 81 (52%)
- INFERRED: 74 (48%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*