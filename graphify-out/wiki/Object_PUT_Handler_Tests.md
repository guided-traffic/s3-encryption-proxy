# Object PUT Handler Tests

> 64 nodes · cohesion 0.12

## Key Concepts

- **objectput_coverage_test.go** (56 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutnewHandler()** (42 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdo()** (37 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutpayload()** (35 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutcapturePut()** (18 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutparseError()** (16 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutwireMultipart()** (15 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdigest()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutreadBack()** (11 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartRoundTripsThroughEveryStage()** (10 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutdropCall()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutCustomMetadataPrefixIsUsedEverywhere()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutNoneProviderPassesPlaintextThrough()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutSmallObjectStoresCiphertextAndAnswers200()** (9 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartNoneProviderSkipsTheSelfCopy()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartNoneProviderStillAbortsTheS3Upload()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartReportsOriginalFailureWhenCleanupAlsoFails()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartSelfCopyFailureIsReportedAsAnError()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartSelfCopyFailureLeaksTheEncryptionSession()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartStopsFeedingAfterAPartFails()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForceCTRContentTypeSelectsCTRAtEverySize()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutForwardsOnlyTheEntityHeadersOnSinglePartPaths()** (8 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- *... and 39 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (41 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (2 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (1 shared connections)
- [CreateMultipartUpload Backend Method](CreateMultipartUpload_Backend_Method.md) (1 shared connections)
- [CompleteMultipartUpload Backend Method](CompleteMultipartUpload_Backend_Method.md) (1 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (1 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (1 shared connections)
- [PutObject Backend Method](PutObject_Backend_Method.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/objectput_coverage_test.go`
- `internal/proxy/handlers/object/operations.go`

## Audit Trail

- EXTRACTED: 302 (99%)
- INFERRED: 3 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*