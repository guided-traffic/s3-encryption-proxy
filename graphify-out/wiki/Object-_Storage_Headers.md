# Object: Storage Headers

> 22 nodes · cohesion 0.14

## Key Concepts

- **.putObjectAutoMultipart()** (22 connections) — `internal/proxy/handlers/object/operations.go`
- **ReadUploadHeaders()** (10 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **Exit provider pass-through on every path** (9 connections) — `docs/developer/request-paths.md`
- **optionalString()** (9 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **CleanupContext()** (8 connections) — `internal/proxy/utils/utils.go`
- **EntityHeaders** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **StorageAttributes** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **ConditionalHeaders** (7 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **ReadEntityHeaders()** (5 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **ReadStorageAttributes()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToCreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToPutObject()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToCreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToPutObject()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.Base64()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **StripAWSChunked()** (3 connections) — `internal/proxy/handlers/object/content_encoding.go`
- **TestStripAWSChunked()** (3 connections) — `internal/proxy/handlers/object/content_encoding_test.go`
- **TestUtlCleanupContext()** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **.ApplyToCompleteMultipartUpload()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToGetObject()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToHeadObject()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.ApplyToPutObject()** (3 connections) — `internal/proxy/handlers/object/storage_headers.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (16 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (7 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (5 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (3 shared connections)
- [Server and Listings](Server_and_Listings.md) (3 shared connections)
- [Misc (42)](Misc_42.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Misc (5)](Misc_5.md) (2 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (1 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/operations.go`
- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`

## Audit Trail

- EXTRACTED: 76 (78%)
- INFERRED: 22 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*