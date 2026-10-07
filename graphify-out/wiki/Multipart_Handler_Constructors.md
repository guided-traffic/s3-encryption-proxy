# Multipart Handler Constructors

> 26 nodes · cohesion 0.23

## Key Concepts

- **setupMultipartTestEnv()** (29 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **multipart_test.go** (26 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **NewCreateHandler()** (24 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewUploadHandler()** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
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
- **TestUploadHandlerASlowPartKeepsItsUploadAlive()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestAbortHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_ForwardsUserMetadata()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_Handle()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCreateHandler_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestListHandler_HandleListParts_HostileKeyStaysWellFormedXML()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **contextState** (3 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.record()** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (26 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (19 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (3 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (3 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (2 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Multipart ListParts Handler](Multipart_ListParts_Handler.md) (2 shared connections)
- [Multipart Complete Handler](Multipart_Complete_Handler.md) (1 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (1 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (1 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/upload.go`

## Audit Trail

- EXTRACTED: 102 (73%)
- INFERRED: 38 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*