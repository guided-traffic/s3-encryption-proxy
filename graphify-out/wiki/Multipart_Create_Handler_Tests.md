# Multipart Create Handler Tests

> 23 nodes · cohesion 0.21

## Key Concepts

- **setupMultipartTestEnv()** (27 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **NewCreateHandler()** (22 connections) — `internal/proxy/handlers/multipart/create.go`
- **multipart/multipart_test.go** (22 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **assertDetachedContext()** (6 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_MetadataCopySurvivesClientDisconnect()** (6 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestMultipartHandlers_Integration()** (6 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestAbortHandler_AbortSurvivesCancelledRequestContext()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_Handle()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_Handle_CopyObjectFailure()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_HostileKeyStaysWellFormedXML()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_SelfCopyPreservesStoredAttributes()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_AbortSurvivesCancelledRequestContext()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_HandleStandard()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestUploadHandler_HandleStreaming()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestAbortHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_ForwardsUserMetadata()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestListHandler_HandleListParts_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **contextState** (3 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **create.go** (2 connections) — `internal/proxy/handlers/multipart/create.go`
- **.record()** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **github.com/stretchr/testify/mock.Arguments** (1 connections)

## Relationships

- [Multipart Handler Construction](Multipart_Handler_Construction.md) (26 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (17 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (4 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (3 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/multipart_test.go`

## Audit Trail

- EXTRACTED: 79 (75%)
- INFERRED: 26 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*