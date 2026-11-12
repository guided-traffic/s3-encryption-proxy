# Object Checksum Agreement Tests

> 78 nodes · cohesion 0.10

## Key Concepts

- **objectput_coverage_test.go** (121 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutnewHandler()** (52 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdo()** (48 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutpayload()** (41 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutcapturePut()** (28 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutwireMultipart()** (20 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutparseError()** (19 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdigest()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutreadBack()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartRoundTripsThroughEveryStage()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutSmallObjectStoresCiphertextAndAnswers200()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartForwardsTheStorageHeaders()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutCustomMetadataPrefixIsUsedEverywhere()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesPlaintextThrough()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForwardsTheStorageHeadersOnTheSingleRequestPath()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjCrcwant()** (8 connections) — `internal/proxy/handlers/object/checksum_echo_test.go`
- **TestObjCrcARefusedUploadStatesNoChecksum()** (8 connections) — `internal/proxy/handlers/object/checksum_echo_test.go`
- **ObjPutdropCall()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartExitProviderStillAbortsTheS3Upload()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartReportsOriginalFailureWhenCleanupAlsoFails()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesThroughTheProducerToo()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForceCTRContentTypeIsNowAnOrdinaryContentType()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- *... and 53 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (69 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (50 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (6 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Harness: Verdict](Harness-_Verdict.md) (1 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Configuration Loading](Configuration_Loading.md) (1 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)
- [Misc (19)](Misc_19.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/checksum_echo_test.go`
- `internal/proxy/handlers/object/etag_marker_test.go`
- `internal/proxy/handlers/object/objectput_coverage_test.go`

## Audit Trail

- EXTRACTED: 412 (91%)
- INFERRED: 43 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*