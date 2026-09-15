# Velero E2E Backup Suite

> 93 nodes · cohesion 0.09

## Key Concepts

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
- **deleteNamespaceAndWait()** (13 connections) — `test/e2e/velero/e2e_test.go`
- *... and 68 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (58 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (34 shared connections)
- [Shutdown](Shutdown.md) (6 shared connections)
- [Stored](Stored.md) (5 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (2 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)
- [Rclone](Rclone.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (1 shared connections)

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

- EXTRACTED: 265 (55%)
- INFERRED: 219 (45%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*