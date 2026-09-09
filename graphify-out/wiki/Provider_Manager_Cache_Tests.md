# Provider Manager Cache Tests

> 15 nodes · cohesion 0.20

## Key Concepts

- **providers_test.go** (9 connections) — `internal/orchestration/providers_test.go`
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **TestProviderManager_Cache()** (5 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_EncryptDecryptDEK()** (5 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_NoneProvider()** (5 connections) — `internal/orchestration/providers_test.go`
- **.DecryptDEK()** (5 connections) — `internal/orchestration/providers_test.go`
- **.EncryptDEK()** (5 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_GetProviderInfo()** (4 connections) — `internal/orchestration/providers_test.go`
- **TestNewProviderManager()** (3 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_NewProviderManager()** (3 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_ValidateConfiguration()** (3 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_CacheLRUEviction()** (2 connections) — `internal/orchestration/providers_test.go`
- **.Fingerprint()** (2 connections) — `internal/orchestration/providers_test.go`
- **.SetFingerprint()** (1 connections) — `internal/orchestration/providers_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (8 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (7 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (2 shared connections)

## Source Files

- `internal/orchestration/providers_test.go`

## Audit Trail

- EXTRACTED: 35 (83%)
- INFERRED: 7 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*