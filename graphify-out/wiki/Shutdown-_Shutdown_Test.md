# Shutdown: Shutdown Test

> 8 nodes · cohesion 0.43

## Key Concepts

- **TestShutdownEndsOpenMultipartUploadsUnderSIGTERM()** (11 connections) — `test/integration/shutdown/shutdown_test.go`
- **docker()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **waitForExit()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **preflight()** (6 connections) — `test/integration/shutdown/shutdown_test.go`
- **openUploads()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **restartProxy()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **proxyLogs()** (4 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdownBudget()** (4 connections) — `test/integration/shutdown/shutdown_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (6 shared connections)
- [Tampering Harness](Tampering_Harness.md) (4 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (1 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (1 shared connections)

## Source Files

- `test/integration/shutdown/shutdown_test.go`

## Audit Trail

- EXTRACTED: 37 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*