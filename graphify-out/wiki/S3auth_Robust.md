# S3auth Robust

> 14 nodes · cohesion 0.27

## Key Concepts

- **S3AuthenticationService** (16 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.AuthenticateRequest()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateSignature()** (7 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildCanonicalRequest()** (6 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **SignatureInfo** (5 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **s3auth_robust.go** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildCanonicalHeaders()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.validateTimestamp()** (4 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.calculateSignature()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.logSecurityEvent()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.parseAuthorizationHeader()** (3 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **stripExcessSpaces()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.buildStringToSign()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`
- **.hmacSHA256()** (2 connections) — `internal/proxy/middleware/s3auth_robust.go`

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (6 shared connections)
- [S3auth Presigned](S3auth_Presigned.md) (4 shared connections)
- [SigV4 Service Coverage Tests](SigV4_Service_Coverage_Tests.md) (3 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [Server](Server.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/s3auth_robust.go`

## Audit Trail

- EXTRACTED: 40 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*