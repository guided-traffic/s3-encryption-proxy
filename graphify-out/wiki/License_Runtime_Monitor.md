# License Runtime Monitor

> 5 nodes · cohesion 0.60

## Key Concepts

- **LicenseValidator** (5 connections) — `internal/license/validator.go`
- **.StartRuntimeMonitoring()** (4 connections) — `internal/license/validator.go`
- **.gracefulShutdown()** (2 connections) — `internal/license/validator.go`
- **.Stop()** (2 connections) — `internal/license/validator.go`
- **.ValidateProviderType()** (1 connections) — `internal/license/validator.go`

## Relationships

- [License Types](License_Types.md) (2 shared connections)

## Source Files

- `internal/license/validator.go`

## Audit Trail

- EXTRACTED: 8 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*