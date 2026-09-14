# SigV4 Signing Helper

> 18 nodes · cohesion 0.22

## Key Concepts

- **time.Time** (21 connections)
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **Handler** (8 connections) — `internal/proxy/handlers/health/handler.go`
- **.SignRequest()** (8 connections) — `test/integration/s3_signing_helper.go`
- **SignHTTPRequestForS3()** (7 connections) — `test/integration/s3_signing_helper.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **s3_signing_helper.go** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalHeaders()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalQueryString()** (3 connections) — `test/integration/s3_signing_helper.go`
- **NewAWSV4Signer()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **.hmacSHA256()** (2 connections) — `test/integration/s3_signing_helper.go`
- **health/handler.go** (2 connections) — `internal/proxy/handlers/health/handler.go`
- **.SetRequestTracker()** (1 connections) — `internal/proxy/handlers/health/handler.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (6 shared connections)
- [License Types](License_Types.md) (3 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (2 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (2 shared connections)
- [Pre-Signed URL Authentication](Pre-Signed_URL_Authentication.md) (2 shared connections)
- [Health Handler](Health_Handler.md) (2 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (2 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (1 shared connections)
- [ListBuckets XML Types](ListBuckets_XML_Types.md) (1 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [Object Listing](Object_Listing.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/health/handler.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 63 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*