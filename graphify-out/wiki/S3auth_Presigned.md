# S3auth Presigned

> 17 nodes · cohesion 0.18

## Key Concepts

- **canonicalQueryString()** (8 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **s3auth_presigned.go** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **S3AuthenticationService** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.authenticatePresigned()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildPresignedCanonicalRequest()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.validatePresignExpiry()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **uriEncode()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **isPresignedRequest()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **parseCredentialScope()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **TestAuthCanonicalQueryIsSortedByName()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalQueryString()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalURI()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestURIEncode()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **net/url.Values** (2 connections)
- **.maxClockSkewSeconds()** (2 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.maxPresignExpirySeconds()** (2 connections) — `internal/proxy/middleware/s3auth_presigned.go`

## Relationships

- [S3auth Robust](S3auth_Robust.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (4 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (3 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [SigV4 Service Coverage Tests](SigV4_Service_Coverage_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 34 (79%)
- INFERRED: 9 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*