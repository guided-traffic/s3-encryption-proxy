# Conditional Request Tests

> 11 nodes · cohesion 0.45

## Key Concepts

- **conditional_requests_test.go** (10 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **TestCondGetAndHeadPreconditions()** (10 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condGet()** (9 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **TestCondETagRoundTripIsSelfConsistent()** (9 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condHead()** (8 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPutObject()** (6 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPrecondition** (4 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condOutcome** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condCodeOf()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPayload()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condStatusOf()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`

## Relationships

- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (3 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (3 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (2 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/conditional_requests_test.go`

## Audit Trail

- EXTRACTED: 43 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*