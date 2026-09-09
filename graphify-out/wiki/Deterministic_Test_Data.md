# Deterministic Test Data

> 7 nodes · cohesion 0.38

## Key Concepts

- **TestLargeMultipart500MB()** (4 connections) — `test/integration/180-degree-variants/large_multipart_upload_test.go`
- **simplePRNG** (3 connections) — `test/integration/180-degree-variants/test_constants.go`
- **test_constants.go** (3 connections) — `test/integration/180-degree-variants/test_constants.go`
- **generateDeterministicData()** (3 connections) — `test/integration/180-degree-variants/test_constants.go`
- **newSimplePRNG()** (3 connections) — `test/integration/180-degree-variants/test_constants.go`
- **.next()** (1 connections) — `test/integration/180-degree-variants/test_constants.go`
- **large_multipart_upload_test.go** (1 connections) — `test/integration/180-degree-variants/large_multipart_upload_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (1 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (1 shared connections)

## Source Files

- `test/integration/180-degree-variants/large_multipart_upload_test.go`
- `test/integration/180-degree-variants/test_constants.go`

## Audit Trail

- EXTRACTED: 8 (80%)
- INFERRED: 2 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*