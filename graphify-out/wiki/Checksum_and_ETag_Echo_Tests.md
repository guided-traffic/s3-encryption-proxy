# Checksum and ETag Echo Tests

> 78 nodes · cohesion 0.11

## Key Concepts

- **objectput_coverage_test.go** (60 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutnewHandler()** (52 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdo()** (48 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutpayload()** (41 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutcapturePut()** (28 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutwireMultipart()** (20 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutparseError()** (19 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartRoundTripsThroughEveryStage()** (12 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdigest()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutreadBack()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutSmallObjectStoresCiphertextAndAnswers200()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **object/checksum_echo_test.go** (10 connections) — `internal/proxy/handlers/object/checksum_echo_test.go`
- **TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartForwardsTheStorageHeaders()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutCustomMetadataPrefixIsUsedEverywhere()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesPlaintextThrough()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutExitProviderPassesThroughTheProducerToo()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForwardsTheStorageHeadersOnTheSingleRequestPath()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutOneBytePastThePartBoundaryUsesTheProducer()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjCrcwant()** (8 connections) — `internal/proxy/handlers/object/checksum_echo_test.go`
- **TestObjCrcARefusedUploadStatesNoChecksum()** (8 connections) — `internal/proxy/handlers/object/checksum_echo_test.go`
- **ObjPutdropCall()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartExitProviderStillAbortsTheS3Upload()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- *... and 53 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (50 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (10 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (2 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (1 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (1 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/checksum_echo_test.go`
- `internal/proxy/handlers/object/etag_marker_test.go`
- `internal/proxy/handlers/object/objectput_coverage_test.go`

## Audit Trail

- EXTRACTED: 352 (89%)
- INFERRED: 43 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*