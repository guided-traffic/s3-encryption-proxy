# Harness: Backend

> 10 nodes · cohesion 0.24

## Key Concepts

- **BackendClient()** (19 connections) — `test/e2e/harness/backend.go`
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

- [s3cmd E2E Suite](s3cmd_E2E_Suite.md) (11 shared connections)
- [Rclone: Rclone Test](Rclone-_Rclone_Test.md) (10 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (10 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [Tampering Harness](Tampering_Harness.md) (6 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (5 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Harness: Exec](Harness-_Exec.md) (1 shared connections)

## Source Files

- `test/e2e/harness/backend.go`

## Audit Trail

- EXTRACTED: 65 (96%)
- INFERRED: 3 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*