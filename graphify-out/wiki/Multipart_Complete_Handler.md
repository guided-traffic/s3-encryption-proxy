# Multipart Complete Handler

> 7 nodes · cohesion 0.38

## Key Concepts

- **complete.go** (8 connections) — `internal/proxy/handlers/multipart/complete.go`
- **completionLocation()** (5 connections) — `internal/proxy/handlers/multipart/complete.go`
- **create.go** (4 connections) — `internal/proxy/handlers/multipart/create.go`
- **CompleteMultipartUpload** (4 connections) — `internal/proxy/handlers/multipart/complete.go`
- **Exit provider pass-through on every path** (3 connections) — `docs/developer/request-paths.md`
- **firstForwardedValue()** (2 connections) — `internal/proxy/handlers/multipart/complete.go`
- **CompletedPart** (2 connections) — `internal/proxy/handlers/multipart/complete.go`

## Relationships

- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (3 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (2 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (1 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/create.go`

## Audit Trail

- EXTRACTED: 18 (90%)
- INFERRED: 2 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*