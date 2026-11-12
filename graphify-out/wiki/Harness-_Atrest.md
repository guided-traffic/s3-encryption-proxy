# Harness: Atrest

> 15 nodes · cohesion 0.23

## Key Concepts

- **DemoStack()** (16 connections) — `test/e2e/harness/harness.go`
- **TestS7_EncryptionAtRest()** (15 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **AssertEncryptedAtRest()** (13 connections) — `test/e2e/harness/atrest.go`
- **TestR7_EncryptionAtRest()** (13 connections) — `test/e2e/rclone/scenarios_atrest_test.go`
- **ListStored()** (11 connections) — `test/e2e/harness/stored.go`
- **MD5File()** (6 connections) — `test/e2e/harness/hash.go`
- **storedFormat()** (6 connections) — `test/e2e/rclone/rclone_test.go`
- **Format** (5 connections) — `test/e2e/harness/atrest.go`
- **UserMetadata()** (5 connections) — `test/e2e/harness/stored.go`
- **storedFormat()** (5 connections) — `test/e2e/s3cmd/s3cmd_test.go`
- **MD5Base64File()** (4 connections) — `test/e2e/harness/hash.go`
- **StoredObject** (4 connections) — `test/e2e/harness/stored.go`
- **MetadataValue()** (4 connections) — `test/e2e/harness/stored.go`
- **storedByKey()** (4 connections) — `test/e2e/s3cmd/scenarios_atrest_test.go`
- **TestUserMetadataIsNilWhenNothingIsLeft()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (11 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (10 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (9 shared connections)
- [Harness: Backend](Harness-_Backend.md) (7 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (4 shared connections)
- [Rclone: Scenarios Read Test](Rclone-_Scenarios_Read_Test.md) (3 shared connections)
- [Misc (15)](Misc_15.md) (2 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (2 shared connections)
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

## Audit Trail

- EXTRACTED: 73 (81%)
- INFERRED: 17 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*