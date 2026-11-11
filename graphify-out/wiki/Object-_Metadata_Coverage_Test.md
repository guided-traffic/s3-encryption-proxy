# Object: Metadata Coverage Test

> 25 nodes · cohesion 0.13

## Key Concepts

- **object/metadata_coverage_test.go** (39 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **ObjMiscnewHandlerWithPrefix()** (11 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **copyWithPooledBuffer()** (9 connections) — `internal/proxy/handlers/object/helpers.go`
- **TestObjMiscUnmatchedMetadataPrefixRefusesInsteadOfLeaking()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscVersionIDReachesHeadAndGet()** (8 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **testLogEntry()** (8 connections) — `internal/proxy/handlers/object/object_test.go`
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
- **TestObjMiscObjectVersionIDReadsTheQueryParameter()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteEntityHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteSSEHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **TestObjMiscWriteVersionHeaders()** (3 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **MockS3Backend** (2 connections)
- **ObjMiscshortWriter** (2 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **Handler** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (23 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (16 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (11 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (4 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (2 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (2 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`

## Audit Trail

- EXTRACTED: 83 (76%)
- INFERRED: 26 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*