# Orchestration: Providers Coverage Test (2)

> 18 nodes · cohesion 0.14

## Key Concepts

- **New()** (15 connections) — `pkg/encryption/storedobject/storedobject.go`
- **OrcMetaCachingManager()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **.Name()** (7 connections) — `pkg/encryption/interfaces.go`
- **OrcMetaCountingKEK** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **sync/atomic.Int64** (4 connections)
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheReturnsSharedStorage()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaEncryptDEKSurfacesKEKFailure()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestFacKeyEncryptionTypeConstants()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestNewReportsAWrapFailure()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.Name()** (2 connections) — `pkg/encryption/keyencryption/aes.go`
- **.newSegmentedObject()** (2 connections) — `internal/orchestration/segmented.go`
- **.Fingerprint()** (2 connections) — `internal/orchestration/providers_coverage_test.go`
- **.Name()** (2 connections) — `internal/orchestration/providers_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (12 shared connections)
- [Tampering Harness](Tampering_Harness.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (9 shared connections)
- [Factory: Factory](Factory-_Factory.md) (5 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (2 shared connections)
- [Conformance Suite](Conformance_Suite.md) (1 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (1 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/segmented.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/storedobject/storedobject.go`
- `pkg/encryption/storedobject/storedobject_test.go`

## Audit Trail

- EXTRACTED: 57 (83%)
- INFERRED: 12 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*