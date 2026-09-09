# Bucket Location and Logging Tests

> 33 nodes · cohesion 0.09

## Key Concepts

- **testHandler()** (16 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **logging_test.go** (8 connections) — `internal/proxy/handlers/bucket/logging_test.go`
- **policy_test.go** (8 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **location_test.go** (7 connections) — `internal/proxy/handlers/bucket/location_test.go`
- **setupTestHandler()** (7 connections) — `internal/proxy/handlers/bucket/policy_test.go`
- **testLogger()** (7 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **TestHandleBucketCORS_GET_NoClient()** (4 connections) — `internal/proxy/handlers/bucket/cors_test.go`
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
- *... and 8 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (25 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (5 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (1 shared connections)
- [Bucket Query Routing Tests](Bucket_Query_Routing_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/cors_test.go`
- `internal/proxy/handlers/bucket/location_test.go`
- `internal/proxy/handlers/bucket/logging_test.go`
- `internal/proxy/handlers/bucket/policy_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 59 (73%)
- INFERRED: 22 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*