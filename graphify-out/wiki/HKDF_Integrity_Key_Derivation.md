# HKDF Integrity Key Derivation

> 11 nodes · cohesion 0.33

## Key Concepts

- **HKDFConfig** (8 connections) — `internal/validation/hkdf.go`
- **hkdf.go** (4 connections) — `internal/validation/hkdf.go`
- **.DeriveIntegrityKey()** (4 connections) — `internal/validation/hkdf.go`
- **HKDFResult** (4 connections) — `internal/validation/hkdf.go`
- **DeriveIntegrityKey()** (3 connections) — `internal/validation/hkdf.go`
- **.DeriveIntegrityKeyWithRandomSalt()** (3 connections) — `internal/validation/hkdf.go`
- **.DeriveIntegrityKeyWithSalt()** (3 connections) — `internal/validation/hkdf.go`
- **.getHashFunction()** (3 connections) — `internal/validation/hkdf.go`
- **.Validate()** (3 connections) — `internal/validation/hkdf.go`
- **hash.Hash** (2 connections)
- **.GenerateRandomSalt()** (2 connections) — `internal/validation/hkdf.go`

## Relationships

- [HKDF Derivation Tests](HKDF_Derivation_Tests.md) (2 shared connections)
- [HMAC Calculator Implementation](HMAC_Calculator_Implementation.md) (1 shared connections)

## Source Files

- `internal/validation/hkdf.go`

## Audit Trail

- EXTRACTED: 21 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*