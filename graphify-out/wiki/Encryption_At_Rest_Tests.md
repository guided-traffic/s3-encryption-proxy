# Encryption At Rest Tests

> 34 nodes · cohesion 0.25

## Key Concepts

- **RandomString()** (51 connections) — `test/integration/minio_test_helper.go`
- **encryption_at_rest_test.go** (32 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncEveryPutPathStoresCiphertext()** (17 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncReadStored()** (16 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncAWSChunkedFramingStoresCiphertext()** (16 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientDrivenMultipartStoresCiphertext()** (15 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncNewMarker()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPayload()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncCopyObjectNeverStoresPlaintext()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertEncryptedAtRest()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPutSimple()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientMetadataCannotReachTheStoredEnvelope()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncStreamedPutWithoutContentLengthStoresCiphertext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncUploadPartCopyNeverStoresPlaintext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertNoMetadataLeak()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertRoundTrip()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncOverwriteReencrypts()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncStoredHMACEnforcement()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncTamperedCiphertextIsRejected()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncOracleBucket()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncViewObject()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncSHA256()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertBodyIsCiphertext()** (7 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncCompareViews()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (31 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (25 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (8 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (7 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (7 shared connections)
- [Range Request Conformance Tests](Range_Request_Conformance_Tests.md) (6 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (4 shared connections)
- [Multipart Conformance Tests](Multipart_Conformance_Tests.md) (4 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (3 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (3 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 242 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*