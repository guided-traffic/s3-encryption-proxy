# S3 Signing Helper

> 13 nodes · cohesion 0.32

## Key Concepts

- **time.Time** (34 connections)
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **.SignRequest()** (8 connections) — `test/integration/s3_signing_helper.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **pacedBody** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.createCanonicalHeaders()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalQueryString()** (3 connections) — `test/integration/s3_signing_helper.go`
- **.hmacSHA256()** (2 connections) — `test/integration/s3_signing_helper.go`
- **.Read()** (1 connections) — `internal/proxy/handlers/multipart/multipart_test.go`

## Relationships

- [Server](Server.md) (3 shared connections)
- [Types](Types.md) (3 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (3 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (3 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (3 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (2 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (2 shared connections)
- [S3auth Robust](S3auth_Robust.md) (2 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)
- [Backend](Backend.md) (2 shared connections)
- [Object Listing Handler](Object_Listing_Handler.md) (2 shared connections)
- [S3auth Presigned](S3auth_Presigned.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/multipart_test.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 63 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*