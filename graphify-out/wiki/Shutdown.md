# Shutdown

> 9 nodes · cohesion 0.56

## Key Concepts

- **TestShutdownEndsOpenMultipartUploadsUnderSIGTERM()** (11 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdown/shutdown_test.go** (8 connections) — `test/integration/shutdown/shutdown_test.go`
- **docker()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **waitForExit()** (7 connections) — `test/integration/shutdown/shutdown_test.go`
- **preflight()** (6 connections) — `test/integration/shutdown/shutdown_test.go`
- **openUploads()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **restartProxy()** (5 connections) — `test/integration/shutdown/shutdown_test.go`
- **proxyLogs()** (4 connections) — `test/integration/shutdown/shutdown_test.go`
- **shutdownBudget()** (4 connections) — `test/integration/shutdown/shutdown_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (1 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (1 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (1 shared connections)

## Source Files

- `test/integration/shutdown/shutdown_test.go`

## Audit Trail

- EXTRACTED: 37 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*