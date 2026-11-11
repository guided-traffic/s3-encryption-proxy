# Harness: Atrest

> 21 nodes · cohesion 0.15

## Key Concepts

- **DemoStack()** (16 connections) — `test/e2e/harness/harness.go`
- **TestS7_EncryptionAtRest()** (15 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **AssertEncryptedAtRest()** (13 connections) — `test/e2e/harness/atrest.go`
- **ListStored()** (13 connections) — `test/e2e/harness/stored.go`
- **TestR7_EncryptionAtRest()** (13 connections) — `test/e2e/rclone/scenarios_atrest_test.go`
- **seedCorpus()** (11 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **AssertStoredIsNotPlaintext()** (10 connections) — `test/e2e/harness/atrest.go`
- **MD5File()** (7 connections) — `test/e2e/harness/hash.go`
- **SHA256Bytes()** (6 connections) — `test/e2e/harness/hash.go`
- **storedFormat()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **Format** (5 connections) — `test/e2e/harness/atrest.go`
- **UserMetadata()** (5 connections) — `test/e2e/harness/stored.go`
- **storedFormat()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **MD5Base64File()** (4 connections) — `test/e2e/harness/hash.go`
- **StoredObject** (4 connections) — `test/e2e/harness/stored.go`
- **MetadataValue()** (4 connections) — `test/e2e/harness/stored.go`
- **storedByKey()** (4 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **TestUserMetadataIsNilWhenNothingIsLeft()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **corpus** (2 connections) — `test/e2e/s3cmd/scenarios_read_test.go`
- **statSize()** (2 connections) — `test/e2e/harness/atrest.go`
- **suite** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (19 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (17 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (13 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (12 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Harness: Backend](Harness-_Backend.md) (5 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (4 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Rclone: Scenarios Read Test](Rclone-_Scenarios_Read_Test.md) (3 shared connections)
- [Harness: Harness](Harness-_Harness.md) (2 shared connections)
- [Harness: Exec](Harness-_Exec.md) (1 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)

## Source Files

- `pkg/encryption/storedobject/storedobject_test.go`
- `test/e2e/harness/atrest.go`
- `test/e2e/harness/harness.go`
- `test/e2e/harness/hash.go`
- `test/e2e/harness/stored.go`
- `test/e2e/rclone/rclone_test.go`
- `test/e2e/rclone/scenarios_atrest_test.go`
- `test/e2e/s3cmd/s3cmd_test.go`
- `test/e2e/s3cmd/scenarios_atrest_test.go`
- `test/e2e/s3cmd/scenarios_read_test.go`

## Audit Trail

- EXTRACTED: 97 (83%)
- INFERRED: 20 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*