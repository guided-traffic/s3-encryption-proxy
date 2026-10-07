# E2E Harness Backend Client

> 11 nodes · cohesion 0.38

## Key Concepts

- **BackendClient()** (19 connections) — `test/e2e/harness/backend.go`
- **harness/backend.go** (10 connections) — `test/e2e/harness/backend.go`
- **ProxyClient()** (10 connections) — `test/e2e/harness/backend.go`
- **EmptyAndDeleteBucket()** (8 connections) — `test/e2e/harness/backend.go`
- **ReadViaProxy()** (8 connections) — `test/e2e/harness/backend.go`
- **EnsureBucket()** (7 connections) — `test/e2e/harness/backend.go`
- **EmptyBucket()** (6 connections) — `test/e2e/harness/backend.go`
- **s3Client()** (6 connections) — `test/e2e/harness/backend.go`
- **caTrustingHTTPClient()** (5 connections) — `test/e2e/harness/backend.go`
- **OpenUploads()** (5 connections) — `test/e2e/harness/backend.go`
- **ProxyETag()** (5 connections) — `test/e2e/harness/backend.go`

## Relationships

- [rclone E2E Suite](rclone_E2E_Suite.md) (11 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (11 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (10 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (6 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (3 shared connections)
- [E2E Harness Environment](E2E_Harness_Environment.md) (3 shared connections)
- [E2E At-Rest Assertions](E2E_At-Rest_Assertions.md) (2 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)

## Source Files

- `test/e2e/harness/backend.go`

## Audit Trail

- EXTRACTED: 65 (96%)
- INFERRED: 3 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*