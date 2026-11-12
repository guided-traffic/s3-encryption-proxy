# GET Response Writing

> 33 nodes · cohesion 0.11

## Key Concepts

- **CiphertextSize()** (24 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **newEncryptingTestHandler()** (21 connections) — `internal/proxy/handlers/object/object_test.go`
- **objCallAutoMultipart()** (15 connections) — `internal/proxy/handlers/object/object_test.go`
- **testPayload()** (13 connections) — `internal/proxy/handlers/object/object_test.go`
- **partCodec()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestHandleGetObject_VersionIDAndResponseHeaders()** (7 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_StoredChainReadsBackAsPlaintext()** (7 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestForeignObjectIsRefusedOnGetAndHead()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestHandleHeadObject_VersionIDAndPlaintextLength()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ExactMultipleOfThePartSizeKeepsTheTrailer()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_MetadataRidesOnCreateWithoutARewrite()** (6 connections) — `internal/proxy/handlers/object/object_test.go`
- **sealInParts()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **storeSegmentedObject()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_AbortOutlivesClientDisconnect()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ATruncatedStreamIsNotCommitted()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_CompletedUploadIsNotSweptAgain()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ConcurrencyIsTheConfiguredNumber()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ShortBodyAbortsInsteadOfCommitting()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestPutObjectAutoMultipart_ShutdownSweepSeesTheUpload()** (5 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestSegPartWriterRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **Handler** (4 connections)
- **TestSegEncryptReaderRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- **TestSegOpenTrailerRejectsTampering()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegSealTrailerMatchesSequentialWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegOversizeRefused()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (30 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (27 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (7 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (6 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_encrypt_reader_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 131 (87%)
- INFERRED: 19 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*