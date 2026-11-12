# Config: Config

> 13 nodes · cohesion 0.17

## Key Concepts

- **.GetActiveProvider()** (7 connections) — `internal/config/config.go`
- **EncryptionProvider** (7 connections) — `internal/config/config.go`
- **validateProvider()** (7 connections) — `internal/config/config.go`
- **.GetAllProviders()** (5 connections) — `internal/config/config.go`
- **validateAESKey()** (4 connections) — `internal/config/config.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **Provider block ,remain boundary of ErrorUnused** (3 connections) — `docs/developer/configuration.md`
- **TestCfgIsValidProviderType()** (3 connections) — `internal/config/accessors_coverage_test.go`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- **validateProviderConfig()** (3 connections) — `internal/config/config.go`
- **TestCfgValidateProviderTypes()** (3 connections) — `internal/config/validation_coverage_test.go`
- **aesKeyError()** (2 connections) — `internal/config/config.go`
- **.GetProviderAliases()** (2 connections) — `internal/orchestration/providers.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (5 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (3 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Io](Dataencryption-_Segmented_Gcm_Io.md) (1 shared connections)
- [Tickets: 036 High Availability](Tickets-_036_High_Availability.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Factory: Factory](Factory-_Factory.md) (1 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)

## Source Files

- `docs/developer/configuration.md`
- `internal/config/accessors_coverage_test.go`
- `internal/config/config.go`
- `internal/config/validation_coverage_test.go`
- `internal/orchestration/providers.go`

## Audit Trail

- EXTRACTED: 30 (77%)
- INFERRED: 9 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*