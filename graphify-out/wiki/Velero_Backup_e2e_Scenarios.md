# Velero Backup e2e Scenarios

> 92 nodes · cohesion 0.09

## Key Concepts

- **TestV8_EncryptionAtRest()** (29 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV1b_MultipartMetadataRoundTrip()** (24 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV2_CSISnapshotDataMover()** (24 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **preflight()** (23 connections) — `test/e2e/velero/e2e_test.go`
- **TestV6_ScheduleAndDelete()** (23 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **loadVersionsEnv()** (22 connections) — `test/e2e/velero/exec.go`
- **TestV9_ProviderRotation()** (22 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV8b_DataMoverPayloadEncryptedAtRest()** (21 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV10_PresignedLogAccess()** (21 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV1_NamespaceMetadataRoundTrip()** (21 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **waitBackupCompleted()** (20 connections) — `test/e2e/velero/healthcheck.go`
- **TestV4_CSISnapshotWithoutDataMover()** (20 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **velero()** (19 connections) — `test/e2e/velero/exec.go`
- **TestV3_FileSystemBackup()** (19 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **eventually()** (18 connections) — `test/e2e/velero/exec.go`
- **exec.go** (18 connections) — `test/e2e/velero/exec.go`
- **waitRestoreCompleted()** (17 connections) — `test/e2e/velero/healthcheck.go`
- **TestV7_RestoreIntoDifferentNamespace()** (17 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **.assertHealthy()** (17 connections) — `test/e2e/velero/healthcheck.go`
- **applyManifest()** (16 connections) — `test/e2e/velero/exec.go`
- **beginScenario()** (16 connections) — `test/e2e/velero/healthcheck.go`
- **tryKubectl()** (15 connections) — `test/e2e/velero/exec.go`
- **uniqueName()** (15 connections) — `test/e2e/velero/exec.go`
- **TestV5_BackupDownload()** (15 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **backupName()** (14 connections) — `test/e2e/velero/e2e_test.go`
- *... and 67 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `test/e2e/velero/backend.go`
- `test/e2e/velero/e2e_test.go`
- `test/e2e/velero/exec.go`
- `test/e2e/velero/healthcheck.go`
- `test/e2e/velero/scenarios_atrest_test.go`
- `test/e2e/velero/scenarios_lifecycle_test.go`
- `test/e2e/velero/scenarios_metadata_test.go`
- `test/e2e/velero/scenarios_volumes_test.go`
- `test/e2e/velero/workloads.go`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`

## Audit Trail

- EXTRACTED: 449 (51%)
- INFERRED: 434 (49%)
- AMBIGUOUS: 3 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*