# Object Handler Dispatch

> 253 nodes · cohesion 0.03

## Key Concepts

- **New()** (338 connections) — `pkg/encryption/envelope/envelope.go`
- **.Header()** (130 connections) — `internal/monitoring/server_coverage_test.go`
- **ObjMiscnewHandler()** (43 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjGetnewHandler()** (41 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **getobject_coverage_test.go** (39 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetdo()** (37 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetpayload()** (32 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **Handler.Handle (base bucket route guard)** (31 connections) — `internal/proxy/handlers/bucket/handler.go`
- **Handler.handleGetObject (GET object)** (28 connections) — `internal/proxy/handlers/object/operations.go`
- **deleteobjects_coverage_test.go** (25 connections) — `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- **Handler.handleGetObjectRange** (25 connections) — `internal/proxy/handlers/object/range.go`
- **ObjGetstore()** (24 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **dispatch_coverage_test.go** (24 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjGetgetOutput()** (23 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **rangeread_coverage_test.go** (23 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **itoa()** (22 connections) — `test/e2e/velero/hash.go`
- **ComputePlaintextSize()** (21 connections) — `pkg/encryption/ciphertext_size.go`
- **metadata_coverage_test.go** (21 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **writeVersionHeaders()** (20 connections) — `internal/proxy/handlers/object/helpers.go`
- **Handler.handleHeadObject (reports plaintext length)** (20 connections) — `internal/proxy/handlers/object/operations.go`
- **objectVersionID()** (19 connections) — `internal/proxy/handlers/object/helpers.go`
- **object_test.go** (19 connections) — `internal/proxy/handlers/object/object_test.go`
- **response.ErrorWriter.WriteS3Error** (18 connections) — `internal/proxy/response/errors.go`
- **Handler.serveRangeByFullDecryption (GCM fallback)** (18 connections) — `internal/proxy/handlers/object/range.go`
- **ObjGetrangeRequest()** (18 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- *... and 228 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `internal/monitoring/server_coverage_test.go`
- `internal/orchestration/metadata.go`
- `internal/orchestration/rangeread.go`
- `internal/orchestration/singlepart.go`
- `internal/proxy/handlers/bucket/acl_test.go`
- `internal/proxy/handlers/bucket/handler.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/object/delete_object_test.go`
- `internal/proxy/handlers/object/deleteobjects_coverage_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/handler.go`
- `internal/proxy/handlers/object/helpers.go`
- `internal/proxy/handlers/object/metadata.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 1135 (42%)
- INFERRED: 1586 (58%)
- AMBIGUOUS: 2 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*