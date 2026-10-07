# Encryption-at-Rest Assertions

> 40 nodes · cohesion 0.17

## Key Concepts

- **encryption_at_rest_test.go** (53 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncReadStored()** (14 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncEveryPutPathStoresCiphertext()** (14 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertEncryptedAtRest()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPayload()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncAWSChunkedFramingStoresCiphertext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientDrivenMultipartStoresCiphertext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertNoMetadataLeak()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertRoundTrip()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncNewMarker()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPutSimple()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientMetadataInsideThePrefixIsRefused()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncCopyObjectNeverStoresPlaintext()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncViewObject()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncUploadPartCopyNeverStoresPlaintext()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncOracleBucket()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncSHA256()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncOverwriteReencrypts()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncStreamedPutWithoutContentLengthStoresCiphertext()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncForgedEnvelopeMetadataIsRefusedOnEveryAttempt()** (7 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncTamperedCiphertextIsRejected()** (7 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAPICode()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertBodyIsCiphertext()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncCompareViews()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncHTTPStatus()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- *... and 15 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (22 shared connections)
- [Integration Test Imports](Integration_Test_Imports.md) (11 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (7 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (7 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (4 shared connections)
- [Object Lock Imports](Object_Lock_Imports.md) (4 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/encryption_at_rest_test.go`
- `test/integration/s3-methods/sealed_checksum_test.go`

## Audit Trail

- EXTRACTED: 184 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*