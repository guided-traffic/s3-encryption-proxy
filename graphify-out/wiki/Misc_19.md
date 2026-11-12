# Misc (19)

> 14 nodes · cohesion 0.20

## Key Concepts

- **MpuEnv** (23 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (16 connections)
- **.MpuComplete()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuExitUpload()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuUploadPart()** (5 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.upload()** (5 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **RtPxcall** (5 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **.MpuInitiate()** (4 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **ObjMiscallowedMethods()** (3 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **.MpuCompleteBody()** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuCaptureParts()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuOpen()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MockS3Backend** (1 connections)
- **.body()** (1 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Relationships

- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (11 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (10 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (8 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (5 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Health: Handler Coverage Test](Health-_Handler_Coverage_Test.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Audit Trail

- EXTRACTED: 57 (89%)
- INFERRED: 7 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*