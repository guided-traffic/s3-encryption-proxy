# Encryption At Rest Tests

> 33 nodes · cohesion 0.23

## Key Concepts

- **encryption_at_rest_test.go** (56 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
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
- **TestCksPartNumberTenThousandIsRefused()** (8 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **EncAPICode()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncAssertBodyIsCiphertext()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- **EncCompareViews()** (6 connections) — `test/integration/s3-methods/encryption_at_rest_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (24 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (22 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (22 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (13 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (10 shared connections)
- [Misc (15)](Misc_15.md) (7 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (3 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (3 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/encryption_at_rest_test.go`
- `test/integration/s3-methods/sealed_checksum_test.go`

## Audit Trail

- EXTRACTED: 224 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*