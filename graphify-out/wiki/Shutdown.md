# Shutdown

> 14 nodes · cohesion 0.31

## Key Concepts

- **time.Duration** (29 connections)
- **TestShutdownEndsOpenMultipartUploadsUnderSIGTERM()** (11 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdown/shutdown_test.go** (8 connections) — `test/integration/shutdown/shutdown_test.go`
- **sinceStart()** (7 connections) — `internal/orchestration/segmented_session.go`
- **docker()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **waitForExit()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **preflight()** (6 connections) — `test/integration/shutdown/shutdown_test.go`
- **.CleanupExpiredSegmentedSessions()** (5 connections) — `internal/orchestration/segmented_session.go`
- **shutdownTail** (5 connections) — `cmd/s3-encryption-proxy/main.go`
- **openUploads()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **restartProxy()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **.idleFor()** (4 connections) — `internal/orchestration/segmented_session.go`
- **proxyLogs()** (4 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdownBudget()** (4 connections) — `test/integration/shutdown/shutdown_test.go`

## Relationships

- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (6 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (6 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (6 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (3 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (2 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (2 shared connections)
- [Performance](Performance.md) (2 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (2 shared connections)
- [Throughput](Throughput.md) (2 shared connections)
- [Main](Main.md) (2 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (2 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/orchestration/segmented_session.go`
- `test/integration/shutdown/shutdown_test.go`

## Audit Trail

- EXTRACTED: 77 (97%)
- INFERRED: 2 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*