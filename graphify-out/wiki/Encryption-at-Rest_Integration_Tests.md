# Encryption-at-Rest Integration Tests

> 34 nodes · cohesion 0.24

## Key Concepts

- **RandomString()** (50 connections) — `test/integration/minio_test_helper.go`
- **encryption_at_rest_test.go** (31 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncEveryPutPathStoresCiphertext()** (17 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncAWSChunkedFramingStoresCiphertext()** (16 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncReadStored()** (15 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientDrivenMultipartStoresCiphertext()** (15 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncCopyObjectNeverStoresPlaintext()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertEncryptedAtRest()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncNewMarker()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPayload()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientMetadataCannotReachTheStoredEnvelope()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncStreamedPutWithoutContentLengthStoresCiphertext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncUploadPartCopyNeverStoresPlaintext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertNoMetadataLeak()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertRoundTrip()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPutSimple()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncOverwriteReencrypts()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncTamperedCiphertextIsRejected()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncOracleBucket()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncViewObject()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertBodyIsCiphertext()** (7 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncSHA256()** (7 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncCompareViews()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncMultipartUpload()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (29 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (21 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (8 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (8 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (7 shared connections)
- [Range Conformance Tests](Range_Conformance_Tests.md) (6 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (4 shared connections)
- [Multipart Conformance Tests](Multipart_Conformance_Tests.md) (4 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (3 shared connections)
- [Passthrough Operation Tests](Passthrough_Operation_Tests.md) (3 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (3 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (2 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 235 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*