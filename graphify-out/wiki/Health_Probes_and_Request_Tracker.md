# Health Probes and Request Tracker

> 30 nodes · cohesion 0.12

## Key Concepts

- **time.Time** (34 connections)
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **Handler** (10 connections) — `internal/proxy/handlers/health/handler.go`
- **storage_headers.go** (10 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **ReadUploadHeaders()** (10 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.SignRequest()** (8 connections) — `test/integration/s3_signing_helper.go`
- **EntityHeaders** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **StorageAttributes** (8 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.Live()** (5 connections) — `internal/proxy/handlers/health/handler.go`
- **.Ready()** (5 connections) — `internal/proxy/handlers/health/handler.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **ReadEntityHeaders()** (5 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **.track()** (4 connections) — `internal/proxy/handlers/health/handler.go`
- **.writeJSON()** (4 connections) — `internal/proxy/handlers/health/handler.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **ReadStorageAttributes()** (4 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **pacedBody** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.createCanonicalHeaders()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalQueryString()** (3 connections) — `test/integration/s3_signing_helper.go`
- **StripAWSChunked()** (3 connections) — `internal/proxy/handlers/object/content_encoding.go`
- **TestStripAWSChunked()** (3 connections) — `internal/proxy/handlers/object/content_encoding_test.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/handlers/health/handler.go`
- *... and 5 more nodes in this community*

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (13 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (7 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (7 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (5 shared connections)
- [Server](Server.md) (3 shared connections)
- [Types](Types.md) (3 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (3 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)
- [Backend](Backend.md) (2 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (2 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/content_encoding.go`
- `internal/proxy/handlers/object/content_encoding_test.go`
- `internal/proxy/handlers/object/storage_headers.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 113 (96%)
- INFERRED: 5 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*