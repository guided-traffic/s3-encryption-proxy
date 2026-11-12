# S3Enc: Client

> 11 nodes · cohesion 0.29

## Key Concepts

- **New()** (10 connections) — `pkg/s3enc/client.go`
- **Client** (8 connections) — `pkg/s3enc/client.go`
- **randomKey()** (6 connections) — `pkg/s3enc/client_test.go`
- **TestKeyRing()** (5 connections) — `pkg/s3enc/client_test.go`
- **.client()** (5 connections) — `test/integration/s3enc/helpers_test.go`
- **TestNewRefusesBadOptions()** (4 connections) — `pkg/s3enc/client_test.go`
- **TestNewRefusesWeakOrMalformedKeys()** (4 connections) — `pkg/s3enc/client_test.go`
- **TestReservedUserMetadataIsRefused()** (4 connections) — `pkg/s3enc/client_test.go`
- **Options** (3 connections) — `pkg/s3enc/client.go`
- **API** (3 connections) — `pkg/s3enc/client.go`
- **github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager.Client** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (7 shared connections)
- [Factory: Factory](Factory-_Factory.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)

## Source Files

- `pkg/s3enc/client.go`
- `pkg/s3enc/client_test.go`
- `test/integration/s3enc/helpers_test.go`

## Audit Trail

- EXTRACTED: 33 (89%)
- INFERRED: 4 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*