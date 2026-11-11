# Server and Listings

> 44 nodes · cohesion 0.07

## Key Concepts

- **time.Time** (36 connections)
- **Server** (23 connections) — `internal/proxy/server.go`
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **.listObjectsV1()** (10 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.listObjectsV2()** (10 connections) — `internal/proxy/handlers/bucket/listing.go`
- **Handler** (10 connections) — `internal/proxy/handlers/health/handler.go`
- **listing_params.go** (8 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **.SignRequest()** (7 connections) — `test/integration/s3_signing_helper.go`
- **callerOwner()** (6 connections) — `internal/proxy/handlers/bucket/listing.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **formatLastModified()** (5 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **ClientIdentity()** (5 connections) — `internal/proxy/middleware/identity.go`
- **PprofServer** (5 connections) — `internal/monitoring/pprof.go`
- **.HandleListBuckets()** (5 connections) — `internal/proxy/handlers/root/handler.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **S3Timestamp()** (4 connections) — `internal/proxy/response/xml.go`
- **pacedBody** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **net/http.Server** (3 connections)
- **.createCanonicalHeaders()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalQueryString()** (3 connections) — `test/integration/s3_signing_helper.go`
- **clientWantsURLEncoding()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- **decodeBackendValue()** (3 connections) — `internal/proxy/handlers/bucket/listing_params.go`
- *... and 19 more nodes in this community*

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (19 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (5 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (4 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (3 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (3 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (3 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)

## Source Files

- `internal/monitoring/pprof.go`
- `internal/proxy/handlers/bucket/listing.go`
- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/listing_params.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/middleware/identity.go`
- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/response/xml.go`
- `internal/proxy/server.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 131 (87%)
- INFERRED: 19 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*