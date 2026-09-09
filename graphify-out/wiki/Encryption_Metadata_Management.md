# Encryption Metadata Management

> 76 nodes · cohesion 0.07

## Key Concepts

- **NewMetadataManager()** (40 connections) — `internal/orchestration/metadata.go`
- **MetadataManager** (32 connections) — `internal/orchestration/metadata.go`
- **orchestration/metadata_coverage_test.go** (30 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaConfig()** (26 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixPtr()** (25 connections) — `internal/orchestration/metadata_coverage_test.go`
- **metadata_test.go** (15 connections) — `internal/orchestration/metadata_test.go`
- **createTestConfigForMetadata()** (14 connections) — `internal/orchestration/metadata_test.go`
- **OrcMetaAssertOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaNewManager()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaBuildMetadataWritesExactlyTheAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **.BuildMetadataKey()** (7 connections) — `internal/orchestration/metadata.go`
- **TestOrcMetaBuildMetadataOmitsIVWhenEmptyAndKeepsUserMetadata()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaHMACRoundTrip()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaAddStandardMetadataWritesUndocumentedKey()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaCreateMissingKEKError()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEmptyPrefixSwallowsAllClientMetadata()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndDefaultPrefixIsS3EP()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaExtractEncryptionMetadataStripsPrefix()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaExtractRequiredFingerprintSearchOrder()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaFilterEncryptionMetadata()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaFilterMetadataForClientIsCaseSensitive()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaFilterMetadataForClientRemovesEveryPrefixedKey()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGetAlgorithmFromMetadata()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- *... and 51 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (38 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (6 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (2 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (1 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (1 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/metadata.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/metadata_test.go`

## Audit Trail

- EXTRACTED: 202 (84%)
- INFERRED: 39 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*