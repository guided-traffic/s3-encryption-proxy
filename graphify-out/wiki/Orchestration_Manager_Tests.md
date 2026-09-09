# Orchestration Manager Tests

> 39 nodes · cohesion 0.17

## Key Concepts

- **manager_coverage_test.go** (37 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrAESConfig()** (29 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNewManager()** (29 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrPayload()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrSHA256()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrEncryptWhole()** (10 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrClearCachesKeepsDecryptionWorking()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrMultipartSessionLifecycle()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrRoundTripBoundarySizes()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrAccessorsAndMetadataFiltering()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrCreateEncryptionAndDecryptionReaders()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrDecryptDataDetectsTamperingForGCMObjects()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrDecryptDataRoutingErrors()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrDecryptDataSkipsHMACForCTRObjects()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrDecryptDataWithoutMetadataServesBackendBytesVerbatim()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrEncryptDataWithContentTypeUnknownFallsBack()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrEncryptDataWithHTTPContentTypeRoundTrip()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrMultipartUploadPartStreamingRoundTrip()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrNoneProviderPassThroughAcrossFacade()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrUploadPartStreamingBufferEncrypted()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrUploadPartStreamingBufferErrors()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNoneConfig()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrDecryptDataWrongObjectKeyFailsForGCM()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrGetMetadataAlgorithm()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrMultipartResultDropsAlgorithmAndFingerprint()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- *... and 14 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (29 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (5 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (3 shared connections)
- [Content Type Factory Selection](Content_Type_Factory_Selection.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager_coverage_test.go`

## Audit Trail

- EXTRACTED: 161 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*