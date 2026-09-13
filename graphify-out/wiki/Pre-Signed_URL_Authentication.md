# Pre-Signed URL Authentication

> 15 nodes · cohesion 0.20

## Key Concepts

- **canonicalQueryString()** (7 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **canonicalURI()** (6 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **s3auth_presigned.go** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.authenticatePresigned()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.buildPresignedCanonicalRequest()** (5 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **S3AuthenticationService** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **uriEncode()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **.validatePresignExpiry()** (4 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **isPresignedRequest()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **parseCredentialScope()** (3 connections) — `internal/proxy/middleware/s3auth_presigned.go`
- **TestCanonicalQueryString()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestCanonicalURI()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **TestURIEncode()** (3 connections) — `internal/proxy/middleware/s3auth_presigned_test.go`
- **net/url.Values** (2 connections)
- **.maxClockSkewSeconds()** (2 connections) — `internal/proxy/middleware/s3auth_presigned.go`

## Relationships

- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (3 shared connections)
- [SigV4 Authentication Tests](SigV4_Authentication_Tests.md) (3 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (2 shared connections)
- [SigV4 Coverage Tests](SigV4_Coverage_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_presigned.go`
- `internal/proxy/middleware/s3auth_presigned_test.go`

## Audit Trail

- EXTRACTED: 30 (79%)
- INFERRED: 8 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*