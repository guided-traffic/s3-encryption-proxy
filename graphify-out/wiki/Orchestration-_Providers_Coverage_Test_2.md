# Orchestration: Providers Coverage Test (2)

> 18 nodes · cohesion 0.14

## Key Concepts

- **New()** (15 connections) — `pkg/encryption/storedobject/storedobject.go`
- **IsReserved()** (8 connections) — `pkg/encryption/storedobject/storedobject.go`
- **s3ep- metadata namespace, filtered out and refused in** (7 connections) — `docs/security/stored-objects.md`
- **UserMetadata()** (7 connections) — `pkg/encryption/storedobject/storedobject.go`
- **.Put()** (6 connections) — `pkg/s3enc/write.go`
- **Response composed from an allowlist, never proxied** (4 connections) — `docs/developer/request-paths.md`
- **TestOrcMetaEncryptDEKSurfacesKEKFailure()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **.cleanMetadata()** (4 connections) — `internal/proxy/handlers/object/helpers.go`
- **Metadata()** (4 connections) — `pkg/encryption/storedobject/storedobject.go`
- **TestIsReservedIgnoresCase()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **TestMetadataDropsEveryUserKeyInsideTheNamespace()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **TestNewReportsAWrapFailure()** (3 connections) — `pkg/encryption/storedobject/storedobject_test.go`
- **.checkUserMetadata()** (3 connections) — `pkg/s3enc/client.go`
- **PutResult** (3 connections) — `pkg/s3enc/write.go`
- **formatKeys()** (3 connections) — `test/integration/s3enc/helpers_test.go`
- **.newSegmentedObject()** (2 connections) — `internal/orchestration/segmented.go`
- **.Copy()** (2 connections) — `pkg/s3enc/write.go`
- **PutOptions** (2 connections) — `pkg/s3enc/write.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (11 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Misc (15)](Misc_15.md) (3 shared connections)
- [Tampering Harness](Tampering_Harness.md) (3 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (2 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (2 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `docs/security/stored-objects.md`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/object/helpers.go`
- `pkg/encryption/storedobject/storedobject.go`
- `pkg/encryption/storedobject/storedobject_test.go`
- `pkg/s3enc/client.go`
- `pkg/s3enc/write.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 50 (81%)
- INFERRED: 12 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*