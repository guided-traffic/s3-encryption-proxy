# Velero E2E Suite

> 92 nodes · cohesion 0.09

## Key Concepts

- **preflight()** (23 connections) — `test/e2e/velero/e2e_test.go`
- **loadVersionsEnv()** (22 connections) — `test/e2e/velero/exec.go`
- **waitBackupCompleted()** (22 connections) — `test/e2e/velero/healthcheck.go`
- **velero()** (20 connections) — `test/e2e/velero/exec.go`
- **exec.go** (19 connections) — `test/e2e/velero/exec.go`
- **waitRestoreCompleted()** (19 connections) — `test/e2e/velero/healthcheck.go`
- **TestV9_ProviderRotation()** (19 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **time.Duration** (18 connections)
- **TestV6_ScheduleAndDelete()** (18 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **TestV1b_MultipartMetadataRoundTrip()** (18 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **tryKubectl()** (17 connections) — `test/e2e/velero/exec.go`
- **beginScenario()** (17 connections) — `test/e2e/velero/healthcheck.go`
- **TestV8_EncryptionAtRest()** (17 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- **TestV2_CSISnapshotDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **TestV4_CSISnapshotWithoutDataMover()** (17 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **applyManifest()** (16 connections) — `test/e2e/velero/exec.go`
- **TestV1_NamespaceMetadataRoundTrip()** (16 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV3_FileSystemBackup()** (16 connections) — `test/e2e/velero/scenarios_volumes_test.go`
- **uniqueName()** (15 connections) — `test/e2e/velero/exec.go`
- **TestV10_PresignedLogAccess()** (15 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **cleanupNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **TestV7_RestoreIntoDifferentNamespace()** (15 connections) — `test/e2e/velero/scenarios_metadata_test.go`
- **backupName()** (14 connections) — `test/e2e/velero/e2e_test.go`
- **kubectl()** (14 connections) — `test/e2e/velero/exec.go`
- **TestV8b_DataMoverPayloadEncryptedAtRest()** (14 connections) — `test/e2e/velero/scenarios_atrest_test.go`
- *... and 67 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (55 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (32 shared connections)
- [Performance Harness](Performance_Harness.md) (5 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (4 shared connections)
- [SigV4 Authentication Tests](SigV4_Authentication_Tests.md) (2 shared connections)
- [License Types](License_Types.md) (1 shared connections)
- [Performance Benchmarks](Performance_Benchmarks.md) (1 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (1 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (1 shared connections)
- [License Tool CLI](License_Tool_CLI.md) (1 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)

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

- EXTRACTED: 257 (54%)
- INFERRED: 220 (46%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*