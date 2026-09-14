# Object PUT Handler Tests

> 62 nodes · cohesion 0.13

## Key Concepts

- **objectput_coverage_test.go** (55 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutnewHandler()** (39 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdo()** (35 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutpayload()** (30 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutwireMultipart()** (19 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutcapturePut()** (17 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutparseError()** (13 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartRoundTripsThroughEveryStage()** (12 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdigest()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutreadBack()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutSmallObjectStoresCiphertextAndAnswers200()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutCustomMetadataPrefixIsUsedEverywhere()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartForwardsOnlyTheEntityHeaders()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesPlaintextThrough()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesThroughTheProducerToo()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutOneBytePastThePartBoundaryUsesTheProducer()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdropCall()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutencryptionMetadata()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartExitProviderStillAbortsTheS3Upload()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartFiltersInjectedEncryptionMetadata()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartReportsOriginalFailureWhenCleanupAlsoFails()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForceCTRContentTypeIsNowAnOrdinaryContentType()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- *... and 37 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (38 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (1 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [Multipart Handler](Multipart_Handler.md) (1 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (1 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (1 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (1 shared connections)
- [Mock: PutObject](Mock-_PutObject.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/objectput_coverage_test.go`

## Audit Trail

- EXTRACTED: 299 (99%)
- INFERRED: 2 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*