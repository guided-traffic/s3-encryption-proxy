# Velero E2E Backup Suite

> 99 nodes · cohesion 0.08

## Key Concepts

- **time.Duration** (29 connections)
- **preflight()** (23 connections) — `test/e2e/velero/e2e_test.go`
- **waitBackupCompleted()** (23 connections) — `test/e2e/velero/healthcheck.go`
- **velero/exec.go** (21 connections) — `test/e2e/velero/exec.go`
- **loadVersionsEnv()** (21 connections) — `test/e2e/velero/exec.go`
- **velero()** (20 connections) — `test/e2e/velero/exec.go`
- **waitRestoreCompleted()** (20 connections) — `test/e2e/velero/healthcheck.go`
- **TestV9_ProviderRotation()** (19 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV6_ScheduleAndDelete()** (18 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV1b_MultipartMetadataRoundTrip()** (18 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **tryKubectl()** (17 connections) — `test/e2e/velero/exec.go`
- **beginScenario()** (17 connections) — `test/e2e/velero/healthcheck.go`
- **TestV8_EncryptionAtRest()** (17 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV2_CSISnapshotDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **TestV4_CSISnapshotWithoutDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **TestV1_NamespaceMetadataRoundTrip()** (16 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV3_FileSystemBackup()** (16 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **applyManifest()** (15 connections) — `test/e2e/velero/exec.go`
- **uniqueName()** (15 connections) — `test/e2e/velero/exec.go`
- **TestV8b_DataMoverPayloadEncryptedAtRest()** (15 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV10_PresignedLogAccess()** (15 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **cleanupNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV7_RestoreIntoDifferentNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **backupName()** (14 connections) — `test/e2e/velero/e2e_test.go`
- **waitDeploymentReady()** (14 connections) — `test/e2e/velero/workloads.go`
- *... and 74 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (59 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (37 shared connections)
- [E2E At-Rest Assertions](E2E_At-Rest_Assertions.md) (9 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (6 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (5 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (3 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (2 shared connections)
- [Performance](Performance.md) (2 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (2 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (2 shared connections)
- [Throughput](Throughput.md) (2 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`
- `test/e2e/harness/atrest.go`
- `test/e2e/harness/stored.go`
- `test/e2e/velero/backend.go`
- `test/e2e/velero/e2e_test.go`
- `test/e2e/velero/exec.go`
- `test/e2e/velero/hash.go`
- `test/e2e/velero/healthcheck.go`
- `test/e2e/velero/scenarios_atrest_test.go`
- `test/e2e/velero/scenarios_lifecycle_test.go`
- `test/e2e/velero/scenarios_metadata_test.go`
- `test/e2e/velero/scenarios_volumes_test.go`
- `test/e2e/velero/workloads.go`

## Audit Trail

- EXTRACTED: 308 (58%)
- INFERRED: 223 (42%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*