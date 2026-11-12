# Server and Listings

> 55 nodes · cohesion 0.06

## Key Concepts

- **time.Time** (36 connections)
- **Server** (22 connections) — `internal/proxy/server.go`
- **S3AuthenticationService** (17 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **AWSV4Signer** (11 connections) — `test/integration/s3_signing_helper.go`
- **Handler** (10 connections) — `internal/proxy/handlers/health/handler.go`
- **.AuthenticateRequest()** (9 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalQueryString()** (8 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.SignRequest()** (7 connections) — `test/integration/s3_signing_helper.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.addAuthorizationHeader()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.createCanonicalRequest()** (5 connections) — `test/integration/s3_signing_helper.go`
- **.authenticatePresigned()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildCanonicalHeaders()** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **SignatureInfo** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.calculateSignature()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createCredentialScope()** (4 connections) — `test/integration/s3_signing_helper.go`
- **.createStringToSign()** (4 connections) — `test/integration/s3_signing_helper.go`
- **uriEncode()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildPresignedCanonicalRequest()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.calculateSignature()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.logSecurityEvent()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateTimestamp()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **pacedBody** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- *... and 30 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (18 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (17 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (10 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (4 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (3 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Middleware: S3Auth Presigned Test](Middleware-_S3Auth_Presigned_Test.md) (3 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Monitoring: Backend](Monitoring-_Backend.md) (2 shared connections)
- [Misc (24)](Misc_24.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/health/handler.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`
- `internal/proxy/middleware/s3auth_robust.go`
- `internal/proxy/server.go`
- `test/integration/s3_signing_helper.go`

## Audit Trail

- EXTRACTED: 144 (82%)
- INFERRED: 32 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*