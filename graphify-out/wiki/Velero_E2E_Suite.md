# Velero E2E Suite

> 94 nodes · cohesion 0.09

## Key Concepts

- **preflight()** (23 connections) — `test/e2e/velero/e2e_test.go`
- **loadVersionsEnv()** (22 connections) — `test/e2e/velero/exec.go`
- **waitBackupCompleted()** (22 connections) — `test/e2e/velero/healthcheck.go`
- **time.Duration** (21 connections)
- **velero()** (20 connections) — `test/e2e/velero/exec.go`
- **waitRestoreCompleted()** (19 connections) — `test/e2e/velero/healthcheck.go`
- **TestV9_ProviderRotation()** (19 connections) — `test/e2e/velero/scenarios_lifecycle_test.go`
- **exec.go** (18 connections) — `test/e2e/velero/exec.go`
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
- *... and 69 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (55 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (32 shared connections)
- [Prometheus Metrics](Prometheus_Metrics.md) (3 shared connections)
- [Single-Part Throughput Tests](Single-Part_Throughput_Tests.md) (2 shared connections)
- [Monitoring Metric Recording](Monitoring_Metric_Recording.md) (2 shared connections)
- [SigV4 Header Auth Tests](SigV4_Header_Auth_Tests.md) (2 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (2 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (1 shared connections)
- [Throughput Benchmark Suite](Throughput_Benchmark_Suite.md) (1 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)

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

- EXTRACTED: 261 (54%)
- INFERRED: 220 (46%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*