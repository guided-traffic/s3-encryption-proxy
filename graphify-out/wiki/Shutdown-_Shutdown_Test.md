# Shutdown: Shutdown Test

> 16 nodes · cohesion 0.18

## Key Concepts

- **time.Duration** (26 connections)
- **TestShutdownEndsOpenMultipartUploadsUnderSIGTERM()** (11 connections) — `test/integration/shutdown/shutdown_test.go`
- **docker()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **waitForExit()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **slowReader** (6 connections) — `internal/orchestration/segmented_session_test.go`
- **preflight()** (6 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdownTail** (5 connections) — `cmd/s3-encryption-proxy/main.go`
- **restartProxy()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **slowlyOver()** (4 connections) — `internal/orchestration/segmented_session_test.go`
- **proxyLogs()** (4 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdownBudget()** (4 connections) — `test/integration/shutdown/shutdown_test.go`
- **tbTrickleReader** (3 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **PerformanceMetrics** (2 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **.CleanupExpiredSegmentedSessions()** (2 connections) — `internal/orchestration/segmented_session.go`
- **.Read()** (1 connections) — `internal/orchestration/segmented_session_test.go`
- **.Read()** (1 connections) — `test/integration/s3-methods/transfer_budget_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Misc (15)](Misc_15.md) (7 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (6 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (6 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (4 shared connections)
- [Server and Listings](Server_and_Listings.md) (4 shared connections)
- [Middleware: S3Auth Presigned Test](Middleware-_S3Auth_Presigned_Test.md) (2 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (2 shared connections)
- [Performance Comparison Summary](Performance_Comparison_Summary.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/orchestration/segmented_session.go`
- `internal/orchestration/segmented_session_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/s3-methods/transfer_budget_test.go`
- `test/integration/shutdown/shutdown_test.go`

## Audit Trail

- EXTRACTED: 72 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*