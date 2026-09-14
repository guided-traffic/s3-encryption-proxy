# Authentication Integration Tests

> 15 nodes · cohesion 0.25

## Key Concepts

- **auth_test.go** (13 connections) — `test/integration/authentication/auth_test.go`
- **testRobustS3Authentication()** (8 connections) — `test/integration/authentication/auth_test.go`
- **SimpleTestContext** (5 connections) — `test/integration/authentication/auth_test.go`
- **TestAuthentication()** (5 connections) — `test/integration/authentication/auth_test.go`
- **testS3ClientAuthentication()** (5 connections) — `test/integration/authentication/auth_test.go`
- **NewSimpleTestContext()** (4 connections) — `test/integration/authentication/auth_test.go`
- **createValidAWS4Signature()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testClockSkewProtection()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testEnterpriseSecurityConfiguration()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testRateLimiting()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testSecurityFeatures()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testSecurityMetrics()** (3 connections) — `test/integration/authentication/auth_test.go`
- **testSignatureValidation()** (3 connections) — `test/integration/authentication/auth_test.go`
- **.CleanupTestBucket()** (2 connections) — `test/integration/authentication/auth_test.go`
- **hmacSHA256()** (2 connections) — `test/integration/authentication/auth_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (11 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `test/integration/authentication/auth_test.go`

## Audit Trail

- EXTRACTED: 39 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*