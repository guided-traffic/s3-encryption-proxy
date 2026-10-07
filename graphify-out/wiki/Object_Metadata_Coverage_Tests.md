# Object Metadata Coverage Tests

> 25 nodes · cohesion 0.13

## Key Concepts

- **object/metadata_coverage_test.go** (20 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscnewHandlerWithPrefix()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscVersionIDReachesHeadAndGet()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscDefaultPrefixFiltersMetadataAndReturnsPlaintext()** (7 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscpayload()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscstore()** (6 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscdigest()** (5 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCopyWithPooledBufferIsByteExact()** (5 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCopyWithPooledBufferPropagatesWriteErrors()** (4 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCleanMetadataEdgeInputs()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCleanMetadataHonoursACustomPrefix()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCleanMetadataStripsOnlyThePrefixedKeys()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscCopyWithPooledBufferPropagatesReadErrors()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscEmptyMetadataPrefixSwallowsAllUserMetadata()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscIsEncryptionMetadataBoundaries()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscObjectVersionIDReadsTheQueryParameter()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteEntityHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteSSEHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteVersionHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **MockS3Backend** (2 connections)
- **ObjMiscshortWriter** (2 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **Handler** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (17 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (13 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (7 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)
- [GET Copy Benchmarks](GET_Copy_Benchmarks.md) (1 shared connections)
- [Short-Part Budget and Memory](Short-Part_Budget_and_Memory.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 61 (72%)
- INFERRED: 24 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*