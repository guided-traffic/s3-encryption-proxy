# E2E At-Rest Assertions

> 25 nodes · cohesion 0.13

## Key Concepts

- **TestS7_EncryptionAtRest()** (15 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **ListStored()** (13 connections) — `test/e2e/harness/stored.go`
- **seedCorpus()** (11 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **AssertStoredIsNotPlaintext()** (10 connections) — `test/e2e/harness/atrest.go`
- **TestS5_ReportedDigests()** (10 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **MD5File()** (7 connections) — `test/e2e/harness/hash.go`
- **s3cmd/scenarios_read_test.go** (7 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **harness/hash.go** (6 connections) — `test/e2e/harness/hash.go`
- **ReadStored()** (6 connections) — `test/e2e/harness/stored.go`
- **stored.go** (5 connections) — `test/e2e/harness/stored.go`
- **storedFormat()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **atrest.go** (4 connections) — `test/e2e/harness/atrest.go`
- **Format** (4 connections) — `test/e2e/harness/atrest.go`
- **MD5Base64File()** (4 connections) — `test/e2e/harness/hash.go`
- **StoredObject** (4 connections) — `test/e2e/harness/stored.go`
- **storedByKey()** (4 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **CopyFile()** (3 connections) — `test/e2e/harness/hash.go`
- **UserMetadata()** (3 connections) — `test/e2e/harness/stored.go`
- **lineFor()** (3 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **corpus** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **statSize()** (2 connections) — `test/e2e/harness/atrest.go`
- **s3cmd/scenarios_atrest_test.go** (2 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **oneField()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **reported()** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **suite** (1 connections)

## Relationships

- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (19 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (11 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (9 shared connections)
- [rclone E2E Suite](rclone_E2E_Suite.md) (9 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (3 shared connections)
- [E2E Harness Environment](E2E_Harness_Environment.md) (2 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (2 shared connections)

## Source Files

- `test/e2e/harness/atrest.go`
- `test/e2e/harness/hash.go`
- `test/e2e/harness/stored.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_atrest_test.go`
- `test/e2e/s3cmd/scenarios_read_test.go`

## Audit Trail

- EXTRACTED: 84 (87%)
- INFERRED: 13 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*