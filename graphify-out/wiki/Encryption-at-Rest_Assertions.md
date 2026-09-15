# Encryption-at-Rest Assertions

> 33 nodes · cohesion 0.23

## Key Concepts

- **encryption_at_rest_test.go** (31 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncEveryPutPathStoresCiphertext()** (17 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncAWSChunkedFramingStoresCiphertext()** (16 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientDrivenMultipartStoresCiphertext()** (15 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncReadStored()** (14 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncClientMetadataInsideThePrefixIsRefused()** (14 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncCopyObjectNeverStoresPlaintext()** (13 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertEncryptedAtRest()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncNewMarker()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPayload()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncStreamedPutWithoutContentLengthStoresCiphertext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncUploadPartCopyNeverStoresPlaintext()** (12 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertNoMetadataLeak()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertRoundTrip()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncPutSimple()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncOverwriteReencrypts()** (11 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncForgedEnvelopeMetadataIsRefusedOnEveryAttempt()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **TestEncTamperedCiphertextIsRejected()** (10 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncOracleBucket()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncViewObject()** (9 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncSHA256()** (8 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAPICode()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertBodyIsCiphertext()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncCompareViews()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncHTTPStatus()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (21 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (14 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (10 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (10 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (10 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (7 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (4 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/encryption_at_rest_test.go`

## Audit Trail

- EXTRACTED: 196 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*