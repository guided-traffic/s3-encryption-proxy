# Orchestration: Metadata Coverage Test

> 9 nodes · cohesion 0.33

## Key Concepts

- **OrcMetaNewManager()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaAssertOnlyAllowedKeys()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndDefaultPrefixIsS3EP()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaPrefixComesFromTheConfiguration()** (5 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaConfig()** (4 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixPtr()** (4 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixedKeys()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaSHA256()** (2 connections) — `internal/orchestration/metadata_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (5 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/orchestration/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 27 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*