# Metadata Manager Tests

> 16 nodes · cohesion 0.31

## Key Concepts

- **orchestration/metadata_coverage_test.go** (14 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaConfig()** (10 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixPtr()** (9 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaNewManager()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaAssertOnlyAllowedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersRefuseUnprefixedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndDefaultPrefixIsS3EP()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersRejectMalformedBase64()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersReportMissingFields()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaPrefixedValueWinsOverUnprefixed()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaPrefixResolutionOrder()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixedKeys()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaSHA256()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`
- **Manager** (1 connections)

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (10 shared connections)
- [Metadata Manager](Metadata_Manager.md) (6 shared connections)
- [Config Structure](Config_Structure.md) (2 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [Provider Manager](Provider_Manager.md) (1 shared connections)
- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 49 (84%)
- INFERRED: 9 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*