# S3Enc: Client

> 16 nodes · cohesion 0.17

## Key Concepts

- **New()** (10 connections) — `pkg/s3enc/client.go`
- **Client** (8 connections) — `pkg/s3enc/client.go`
- **randomKey()** (6 connections) — `pkg/s3enc/client_test.go`
- **.Put()** (6 connections) — `pkg/s3enc/write.go`
- **TestKeyRing()** (5 connections) — `pkg/s3enc/client_test.go`
- **.client()** (5 connections) — `test/integration/s3enc/helpers_test.go`
- **TestNewRefusesBadOptions()** (4 connections) — `pkg/s3enc/client_test.go`
- **TestNewRefusesWeakOrMalformedKeys()** (4 connections) — `pkg/s3enc/client_test.go`
- **TestReservedUserMetadataIsRefused()** (4 connections) — `pkg/s3enc/client_test.go`
- **Options** (3 connections) — `pkg/s3enc/client.go`
- **API** (3 connections) — `pkg/s3enc/client.go`
- **.checkUserMetadata()** (3 connections) — `pkg/s3enc/client.go`
- **PutResult** (3 connections) — `pkg/s3enc/write.go`
- **.Copy()** (2 connections) — `pkg/s3enc/write.go`
- **PutOptions** (2 connections) — `pkg/s3enc/write.go`
- **github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager.Client** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (11 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (7 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)
- [Tampering Harness](Tampering_Harness.md) (2 shared connections)
- [Factory: Factory](Factory-_Factory.md) (1 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)

## Source Files

- `pkg/s3enc/client.go`
- `pkg/s3enc/client_test.go`
- `pkg/s3enc/write.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 43 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*