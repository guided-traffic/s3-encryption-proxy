# Middleware: S3Auth Robust

> 25 nodes · cohesion 0.13

## Key Concepts

- **S3AuthenticationService** (19 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.AuthenticateRequest()** (9 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalQueryString()** (8 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.authenticatePresigned()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildCanonicalHeaders()** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **SignatureInfo** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **uriEncode()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildPresignedCanonicalRequest()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.calculateSignature()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.logSecurityEvent()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateTimestamp()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **isPresignedRequest()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **parseCredentialScope()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **TestAuthCanonicalQueryIsSortedByName()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalQueryString()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalURI()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestURIEncode()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **.buildStringToSign()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.parseAuthorizationHeader()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **net/url.Values** (2 connections)
- **stripExcessSpaces()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.hmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (9 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (9 shared connections)
- [Server and Listings](Server_and_Listings.md) (4 shared connections)
- [Middleware: S3Auth Presigned Test](Middleware-_S3Auth_Presigned_Test.md) (3 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (2 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`
- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 57 (71%)
- INFERRED: 23 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*