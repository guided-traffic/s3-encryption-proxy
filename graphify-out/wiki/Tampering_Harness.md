# Tampering Harness

> 26 nodes · cohesion 0.11

## Key Concepts

- **AESProvider** (9 connections) — `pkg/encryption/keyencryption/aes.go`
- **.EncryptDEK()** (7 connections) — `pkg/encryption/interfaces.go`
- **.Fingerprint()** (7 connections) — `pkg/encryption/interfaces.go`
- **.Name()** (7 connections) — `pkg/encryption/interfaces.go`
- **OrcMetaCountingKEK** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (6 connections) — `pkg/encryption/interfaces.go`
- **ExitProvider** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **failingKEK** (5 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **sync/atomic.Int64** (4 connections)
- **.DecryptDEK()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **.EncryptDEK()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **.wrapAEAD()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **.DecryptDEK()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **.EncryptDEK()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/keyencryption/exit.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/keyencryption/exit.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.Fingerprint()** (2 connections) — `pkg/encryption/keyencryption/aes.go`
- **.Name()** (2 connections) — `pkg/encryption/keyencryption/aes.go`
- **.Fingerprint()** (2 connections) — `pkg/encryption/keyencryption/exit.go`
- **.Name()** (2 connections) — `pkg/encryption/keyencryption/exit.go`
- **.Fingerprint()** (2 connections) — `internal/orchestration/providers_coverage_test.go`
- **.Name()** (2 connections) — `internal/orchestration/providers_coverage_test.go`
- **.Fingerprint()** (2 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Misc (15)](Misc_15.md) (10 shared connections)
- [Factory: Factory](Factory-_Factory.md) (6 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (3 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (2 shared connections)
- [Conformance Suite](Conformance_Suite.md) (1 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers_coverage_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/exit.go`
- `pkg/encryption/storedobject/storedobject_test.go`

## Audit Trail

- EXTRACTED: 46 (67%)
- INFERRED: 23 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*