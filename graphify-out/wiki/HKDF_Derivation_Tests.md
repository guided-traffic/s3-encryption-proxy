# HKDF Derivation Tests

> 18 nodes · cohesion 0.20

## Key Concepts

- **NewHKDFConfig()** (11 connections) — `internal/validation/hkdf.go`
- **hkdf_test.go** (11 connections) — `internal/validation/hkdf_test.go`
- **hkdf_coverage_test.go** (5 connections) — `internal/validation/hkdf_coverage_test.go`
- **contains()** (5 connections) — `internal/validation/hkdf_test.go`
- **TestValHKDFConfigDerivationProperties()** (4 connections) — `internal/validation/hkdf_coverage_test.go`
- **ValderiveReference()** (4 connections) — `internal/validation/hkdf_coverage_test.go`
- **TestHKDFConfig_DeriveIntegrityKey()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_DeriveIntegrityKeyWithSalt()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_GenerateRandomSalt()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_Validate()** (4 connections) — `internal/validation/hkdf_test.go`
- **TestValDeriveIntegrityKeyPackageLevel()** (3 connections) — `internal/validation/hkdf_coverage_test.go`
- **BenchmarkHKDFDerivation()** (3 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFConfig_DeriveIntegrityKeyWithRandomSalt()** (3 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFSecurityProperties()** (3 connections) — `internal/validation/hkdf_test.go`
- **TestNewHKDFConfig()** (3 connections) — `internal/validation/hkdf_test.go`
- **TestValHKDFConfigGetHashFunction()** (2 connections) — `internal/validation/hkdf_coverage_test.go`
- **TestHKDFConstants()** (2 connections) — `internal/validation/hkdf_test.go`
- **TestHKDFDifferentHashAlgorithms()** (2 connections) — `internal/validation/hkdf_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (13 shared connections)
- [HKDF Integrity Key Derivation](HKDF_Integrity_Key_Derivation.md) (2 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (1 shared connections)
- [Throughput Benchmark Suite](Throughput_Benchmark_Suite.md) (1 shared connections)

## Source Files

- `internal/validation/hkdf.go`
- `internal/validation/hkdf_coverage_test.go`
- `internal/validation/hkdf_test.go`

## Audit Trail

- EXTRACTED: 38 (81%)
- INFERRED: 9 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*