# Harness: Backend

> 15 nodes · cohesion 0.19

## Key Concepts

- **BackendClient()** (17 connections) — `test/e2e/harness/backend.go`
- **TestR1_SinglePartUpload()** (11 connections) — `test/e2e/rclone/scenarios_upload_test.go`
- **AssertStoredIsNotPlaintext()** (10 connections) — `test/e2e/harness/atrest.go`
- **ProxyClient()** (10 connections) — `test/e2e/harness/backend.go`
- **TestR4_CheckAndSync()** (9 connections) — `test/e2e/rclone/scenarios_sync_test.go`
- **SHA256File()** (8 connections) — `test/e2e/harness/hash.go`
- **EmptyAndDeleteBucket()** (7 connections) — `test/e2e/harness/backend.go`
- **EnsureBucket()** (7 connections) — `test/e2e/harness/backend.go`
- **ReadViaProxy()** (6 connections) — `test/e2e/harness/backend.go`
- **s3Client()** (6 connections) — `test/e2e/harness/backend.go`
- **EmptyBucket()** (5 connections) — `test/e2e/harness/backend.go`
- **ProxyETag()** (5 connections) — `test/e2e/harness/backend.go`
- **OpenUploads()** (4 connections) — `test/e2e/harness/backend.go`
- **SHA256Bytes()** (4 connections) — `test/e2e/harness/hash.go`
- **statSize()** (2 connections) — `test/e2e/harness/atrest.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (15 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (15 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (13 shared connections)
- [Misc (15)](Misc_15.md) (8 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (7 shared connections)
- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (7 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (4 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Rclone: Scenarios Read Test](Rclone-_Scenarios_Read_Test.md) (1 shared connections)

## Source Files

- `test/e2e/harness/atrest.go`
- `test/e2e/harness/backend.go`
- `test/e2e/harness/hash.go`
- `test/e2e/rclone/scenarios_sync_test.go`
- `test/e2e/rclone/scenarios_upload_test.go`

## Audit Trail

- EXTRACTED: 79 (87%)
- INFERRED: 12 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*