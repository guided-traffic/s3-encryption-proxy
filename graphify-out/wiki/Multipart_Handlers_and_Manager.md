# Multipart Handlers and Manager

> 71 nodes · cohesion 0.09

## Key Concepts

- **S3BackendInterface** (83 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/sirupsen/logrus.Entry** (59 connections)
- **Manager** (47 connections) — `internal/orchestration/manager.go`
- **Parser** (40 connections) — `internal/proxy/request/parser.go`
- **ErrorWriter** (33 connections) — `internal/proxy/response/errors.go`
- **setupMultipartTestEnv()** (29 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **XMLWriter** (26 connections) — `internal/proxy/response/xml.go`
- **NewCreateHandler()** (24 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewUploadHandler()** (21 connections) — `internal/proxy/handlers/multipart/upload.go`
- **Handler** (20 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/multipart/handler.go`
- **NewHandler()** (17 connections) — `internal/proxy/handlers/object/handler.go`
- **NewCompleteHandler()** (16 connections) — `internal/proxy/handlers/multipart/complete.go`
- **ListHandler** (14 connections) — `internal/proxy/handlers/multipart/list.go`
- **NewHandler()** (13 connections) — `internal/proxy/handlers/root/handler.go`
- **AbortHandler** (13 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CompleteHandler** (13 connections) — `internal/proxy/handlers/multipart/complete.go`
- **NewAbortHandler()** (12 connections) — `internal/proxy/handlers/multipart/abort.go`
- **CreateHandler** (12 connections) — `internal/proxy/handlers/multipart/create.go`
- **NewListHandler()** (11 connections) — `internal/proxy/handlers/multipart/list.go`
- **TaggingHandler** (11 connections) — `internal/proxy/handlers/object/tagging.go`
- **ACLHandler** (10 connections) — `internal/proxy/handlers/object/acl.go`
- **alignedPlaintext()** (9 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **TestCompleteHandler_AbortSurvivesClientDisconnect()** (9 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **CopyHandler** (9 connections) — `internal/proxy/handlers/multipart/copy.go`
- *... and 46 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (53 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (38 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (34 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (28 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (26 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (15 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (7 shared connections)
- [Manager Tests](Manager_Tests.md) (6 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (6 shared connections)
- [Server and Listings](Server_and_Listings.md) (5 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (5 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (5 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/proxy/handlers/multipart/abort.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/copy.go`
- `internal/proxy/handlers/multipart/copy_test.go`
- `internal/proxy/handlers/multipart/create.go`
- `internal/proxy/handlers/multipart/handler.go`
- `internal/proxy/handlers/multipart/list.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/upload.go`
- `internal/proxy/handlers/object/acl.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/tagging.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/interfaces/s3_backend.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/response/errors.go`

## Audit Trail

- EXTRACTED: 473 (87%)
- INFERRED: 68 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*