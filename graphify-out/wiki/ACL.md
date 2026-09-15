# ACL

> 8 nodes · cohesion 0.32

## Key Concepts

- **acl_test.go** (4 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **.accessControlPolicy()** (3 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **mapCannedACLForBucket()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **parseACLXMLForTest()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **TestACLXMLParsing()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **TestCannedACLMapping()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.AccessControlPolicy** (2 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3/types.BucketCannedACL** (1 connections)

## Relationships

- [Subresource Documents](Subresource_Documents.md) (2 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/acl_test.go`
- `internal/proxy/handlers/bucket/subresource_documents.go`

## Audit Trail

- EXTRACTED: 13 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*