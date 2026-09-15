# Bucket Location and Logging Tests

> 32 nodes · cohesion 0.09

## Key Concepts

- **testHandler()** (15 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **logging_test.go** (8 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **policy_test.go** (8 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **location_test.go** (7 connections) — `internal/proxy/handlers/bucket/location_test.go`
- **setupTestHandler()** (7 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **testLogger()** (6 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **TestHandleBucketLocation_GET_NoClient()** (4 connections) — `internal/proxy/handlers/bucket/location_test.go`
- **TestHandleBucketLogging_GET_NoClient()** (4 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestHandleBucketPolicy_GET_NoClient()** (4 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **bucket/test_helpers_test.go** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **TestBucketLocationErrorHandling()** (3 connections) — `internal/proxy/handlers/bucket/location_test.go`
- **TestBucketLocationMethodHandling()** (3 connections) — `internal/proxy/handlers/bucket/location_test.go`
- **TestBucketLoggingErrorHandling()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingInvalidXML()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingMethodHandling()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingSecurityScenarios()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingTargetValidation()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingXMLFormat()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketLoggingXMLValidation()** (3 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **TestBucketPolicyJSONValidation()** (3 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **TestBucketPolicyMethodHandling()** (3 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **TestBucketPolicyRequestBodyHandling()** (3 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **TestHandleBucketPolicy_DELETE_NoClient()** (3 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **TestHandleBucketPolicy_PUT_NoClient()** (3 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **TestBucketLocationRegionMapping()** (2 connections) — `internal/proxy/handlers/bucket/location_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (23 shared connections)
- [Bucket Crud](Bucket_Crud.md) (4 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/location_test.go`
- `internal/proxy/handlers/bucket/logging_test.go`
- `internal/proxy/handlers/bucket/policy_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 57 (75%)
- INFERRED: 19 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*