# Multipart Handler Unit Tests

> 27 nodes · cohesion 0.21

## Key Concepts

- **setupMultipartTestEnv()** (28 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **multipart_test.go** (24 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **NewCreateHandler()** (23 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewUploadHandler()** (20 connections) — `internal/proxy/handlers/multipart/upload.go`
- **alignedPlaintext()** (9 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_AbortSurvivesClientDisconnect()** (8 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestMultipartHandlers_Integration()** (8 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_Handle()** (7 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_Handle_FinalPartFailure()** (7 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_HostileKeyStaysWellFormedXML()** (7 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_StoredAttributesNeedNoSelfCopy()** (7 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_HandleStandard()** (6 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_HandleStreaming()** (6 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **assertDetachedContext()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestAbortHandler_AbortSurvivesCancelledRequestContext()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_SecondShortPartIsRefused()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_ShortPartIsHeldUntilComplete()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestAbortHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_ForwardsUserMetadata()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestListHandler_HandleListParts_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **contextState** (3 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **create.go** (2 connections) — `internal/proxy/handlers/multipart/create.go`
- **upload.go** (2 connections) — `internal/proxy/handlers/multipart/upload.go`
- *... and 2 more nodes in this community*

## Relationships

- [Multipart Handler](Multipart_Handler.md) (32 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (18 shared connections)
- [Multipart XML Documents](Multipart_XML_Documents.md) (3 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (2 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (1 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (1 shared connections)
- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (1 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/upload.go`

## Audit Trail

- EXTRACTED: 100 (74%)
- INFERRED: 36 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*