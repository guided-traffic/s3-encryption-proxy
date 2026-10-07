# s3cmd E2E Suite

> 25 nodes · cohesion 0.21

## Key Concepts

- **newSuite()** (17 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **s3cmd_test.go** (16 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **preflight()** (16 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **endpoints()** (14 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **WriteRandomFile()** (13 connections) — `test/e2e/harness/hash.go`
- **TestS6_Lifecycle()** (12 connections) — `test/e2e/s3cmd/scenarios_lifecycle_test.go`
- **TestS1_SinglePartPut()** (11 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **SHA256File()** (10 connections) — `test/e2e/harness/hash.go`
- **TestS2_MultipartPut()** (10 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **TestS2b_ProducerObject()** (10 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **TestS4_Sync()** (9 connections) — `test/e2e/s3cmd/scenarios_sync_test.go`
- **writeConfig()** (8 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestPreflight()** (7 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **TestS3_Get()** (7 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **suite** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **s3cmdBin()** (6 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **endpoint** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **uniqueBucket()** (3 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **s3cmd/scenarios_upload_test.go** (3 connections) — `test/e2e/s3cmd/scenarios_upload_test.go`
- **boolWord()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **containsStr()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **stripScheme()** (2 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **.uri()** (1 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **s3cmd/scenarios_lifecycle_test.go** (1 connections) — `test/e2e/s3cmd/scenarios_lifecycle_test.go`
- **s3cmd/scenarios_sync_test.go** (1 connections) — `test/e2e/s3cmd/scenarios_sync_test.go`

## Relationships

- [E2E At-Rest Assertions](E2E_At-Rest_Assertions.md) (19 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (11 shared connections)
- [rclone E2E Suite](rclone_E2E_Suite.md) (10 shared connections)
- [Exec](Exec.md) (5 shared connections)
- [E2E Harness Environment](E2E_Harness_Environment.md) (5 shared connections)
- [Rclone](Rclone.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)

## Source Files

- `test/e2e/harness/hash.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_lifecycle_test.go`
- `test/e2e/s3cmd/scenarios_read_test.go`
- `test/e2e/s3cmd/scenarios_sync_test.go`
- `test/e2e/s3cmd/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 101 (78%)
- INFERRED: 29 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*