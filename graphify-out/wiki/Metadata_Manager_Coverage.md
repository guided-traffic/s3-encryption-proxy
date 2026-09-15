# Metadata Manager Coverage

> 25 nodes · cohesion 0.20

## Key Concepts

- **NewMetadataManager()** (15 connections) — `internal/orchestration/metadata.go`
- **orchestration/metadata_coverage_test.go** (14 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaConfig()** (10 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixPtr()** (9 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaNewManager()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **metadata_test.go** (7 connections) — `internal/orchestration/metadata_test.go`
- **createTestConfigForMetadata()** (7 connections) — `internal/orchestration/metadata_test.go`
- **OrcMetaAssertOnlyAllowedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersRefuseUnprefixedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndDefaultPrefixIsS3EP()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersRejectMalformedBase64()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersReportMissingFields()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaPrefixedValueWinsOverUnprefixed()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaPrefixResolutionOrder()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestNewMetadataManager()** (5 connections) — `internal/orchestration/metadata_test.go`
- **TestGetAlgorithm()** (4 connections) — `internal/orchestration/metadata_test.go`
- **TestGetEncryptedDEK()** (4 connections) — `internal/orchestration/metadata_test.go`
- **TestGetFingerprint()** (4 connections) — `internal/orchestration/metadata_test.go`
- **TestGetMetadataPrefix()** (4 connections) — `internal/orchestration/metadata_test.go`
- **createTestConfigWithoutPrefix()** (3 connections) — `internal/orchestration/metadata_test.go`
- **OrcMetaPrefixedKeys()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaSHA256()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`
- **Manager** (1 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (15 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (5 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (2 shared connections)
- [Metadata](Metadata.md) (2 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/metadata.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/metadata_test.go`

## Audit Trail

- EXTRACTED: 72 (83%)
- INFERRED: 15 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*