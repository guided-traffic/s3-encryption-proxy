# Velero E2E Suite

> 90 nodes · cohesion 0.09

## Key Concepts

- **velero/exec.go** (32 connections) — `test/e2e/velero/exec.go`
- **velero/scenarios_lifecycle_test.go** (24 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **preflight()** (23 connections) — `test/e2e/velero/e2e_test.go`
- **waitBackupCompleted()** (23 connections) — `test/e2e/velero/healthcheck.go`
- **loadVersionsEnv()** (21 connections) — `test/e2e/velero/exec.go`
- **waitRestoreCompleted()** (20 connections) — `test/e2e/velero/healthcheck.go`
- **velero()** (19 connections) — `test/e2e/velero/exec.go`
- **TestV9_ProviderRotation()** (19 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV6_ScheduleAndDelete()** (18 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV1b_MultipartMetadataRoundTrip()** (18 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **tryKubectl()** (17 connections) — `test/e2e/velero/exec.go`
- **healthcheck.go** (17 connections) — `test/e2e/velero/healthcheck.go`
- **beginScenario()** (17 connections) — `test/e2e/velero/healthcheck.go`
- **TestV8_EncryptionAtRest()** (17 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV2_CSISnapshotDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **TestV4_CSISnapshotWithoutDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **TestV1_NamespaceMetadataRoundTrip()** (16 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV3_FileSystemBackup()** (16 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **workloads.go** (16 connections) — `test/e2e/velero/workloads.go`
- **applyManifest()** (15 connections) — `test/e2e/velero/exec.go`
- **uniqueName()** (15 connections) — `test/e2e/velero/exec.go`
- **TestV8b_DataMoverPayloadEncryptedAtRest()** (15 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV10_PresignedLogAccess()** (15 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **cleanupNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV7_RestoreIntoDifferentNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- *... and 65 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (68 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (58 shared connections)
- [Misc (15)](Misc_15.md) (35 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (6 shared connections)
- [Harness: Atrest](Harness-_Atrest.md) (4 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (2 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Rclone: Rclone Test (2)](Rclone-_Rclone_Test_2.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)

## Source Files

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

- EXTRACTED: 318 (59%)
- INFERRED: 219 (41%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*