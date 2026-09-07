# Object PUT and Auto-Multipart

> 130 nodes · cohesion 0.05

## Key Concepts

- **objectput_coverage_test.go** (56 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutnewHandler()** (38 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **Handler.putObjectAutoMultipart (PUT to internal multipart)** (36 connections) — `internal/proxy/handlers/object/operations.go`
- **ObjPutdo()** (35 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutpayload()** (35 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **.putObjectAutoMultipart()** (31 connections) — `internal/proxy/handlers/object/operations.go`
- **Handler.handlePutObject (PUT routing)** (29 connections) — `internal/proxy/handlers/object/operations.go`
- **Handler.putObjectStreamingReader (single-part CTR stream)** (21 connections) — `internal/proxy/handlers/object/operations.go`
- **ComputeCiphertextSize()** (20 connections) — `pkg/encryption/ciphertext_size.go`
- **ObjPutcapturePut()** (19 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartRoundTripsThroughEveryStage()** (18 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **CompleteHandler.Handle (POST ?uploadId)** (17 connections) — `internal/proxy/handlers/multipart/complete.go`
- **ObjPutwireMultipart()** (16 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **CleanupContext()** (16 connections) — `internal/proxy/utils/utils.go`
- **StripAWSChunked()** (15 connections) — `internal/proxy/handlers/object/content_encoding.go`
- **CreateHandler.Handle (POST ?uploads)** (15 connections) — `internal/proxy/handlers/multipart/create.go`
- **TestObjPutSmallObjectStoresCiphertextAndAnswers200()** (15 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **ObjPutparseError()** (14 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartAbortsOnEveryFailureAfterCreate()** (14 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **Handler.putObjectDirect (small objects, AES-GCM)** (14 connections) — `internal/proxy/handlers/object/operations.go`
- **TestObjPutAWSChunkedFramingIsDecodedBeforeEncryption()** (13 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **multipart.(*UploadHandler).handleStreamingUploadPart** (13 connections) — `internal/proxy/handlers/multipart/upload.go`
- **.Handle()** (12 connections) — `internal/proxy/handlers/multipart/create.go`
- **TestObjPutAutoMultipartAcceptsAWSChunkedWithoutDecodedLength()** (12 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- **TestObjPutAutoMultipartNoneProviderSkipsTheSelfCopy()** (12 connections) — `internal/proxy/handlers/object/objectput_coverage_test.go`
- *... and 105 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `docs/architecture/callgraph_orchestration_layer.svg`
- `docs/tickets/010-tier2/proxy-allocs-top20.txt`
- `docs/tickets/010-tier4.1/mem-alloc-space.txt`
- `docs/tickets/010-tier4.1/proxy-allocs-top20.txt`
- `internal/orchestration/manager.go`
- `internal/orchestration/multipart.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/multipart/xml.go`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/objectput_coverage_test.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/request/chunked_decoder.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/utils/utils.go`

## Audit Trail

- EXTRACTED: 789 (70%)
- INFERRED: 339 (30%)
- AMBIGUOUS: 4 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*