# Bucket ACL Tests

> 16 nodes · cohesion 0.17

## Key Concepts

- **bucket_acl_test.go** (7 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **acl_test.go** (5 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **validateCannedACL()** (4 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **mapCannedACLForBucket()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **parseACLXMLForTest()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **TestACLXMLParsing()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **TestCannedACLMapping()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **TestHandleBucketACL_GET_NoClient()** (3 connections) — `internal/proxy/handlers/bucket/acl_test.go`
- **parseACLXML()** (3 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **TestACLSecurityScenarios()** (3 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **TestBucketACLValidation()** (3 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **TestBucketACLXMLValidation()** (3 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.AccessControlPolicy** (2 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3/types.BucketCannedACL** (2 connections)
- **TestACLGranteeTypes()** (2 connections) — `test/integration/s3-methods/bucket_acl_test.go`
- **TestACLPermissionMapping()** (2 connections) — `test/integration/s3-methods/bucket_acl_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/acl_test.go`
- `test/integration/s3-methods/bucket_acl_test.go`

## Audit Trail

- EXTRACTED: 29 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*