# Config: Config

> 17 nodes · cohesion 0.13

## Key Concepts

- **EncryptionProvider** (9 connections) — `internal/config/config.go`
- **startupWarnings()** (7 connections) — `cmd/s3-encryption-proxy/main.go`
- **validateProvider()** (7 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (6 connections) — `internal/config/config.go`
- **DecodeAESKey()** (6 connections) — `pkg/encryption/keyencryption/aes.go`
- **validateAESKey()** (5 connections) — `internal/config/config.go`
- **parseKey()** (5 connections) — `pkg/s3enc/client.go`
- **TestMainStartupWarnings()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **Provider block ,remain boundary of ErrorUnused** (3 connections) — `docs/developer/configuration.md`
- **TestCfgIsValidProviderType()** (3 connections) — `internal/config/accessors_coverage_test.go`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- **validateProviderConfig()** (3 connections) — `internal/config/config.go`
- **TestCfgValidateProviderTypes()** (3 connections) — `internal/config/validation_coverage_test.go`
- **startupWarning** (3 connections) — `cmd/s3-encryption-proxy/main.go`
- **aesKeyError()** (2 connections) — `internal/config/config.go`
- **github.com/sirupsen/logrus.Fields** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (4 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (2 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (2 shared connections)
- [Factory: Factory](Factory-_Factory.md) (2 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [Configuration Loading](Configuration_Loading.md) (1 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`
- `docs/developer/configuration.md`
- `internal/config/accessors_coverage_test.go`
- `internal/config/config.go`
- `internal/config/validation_coverage_test.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/s3enc/client.go`

## Audit Trail

- EXTRACTED: 48 (89%)
- INFERRED: 6 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*