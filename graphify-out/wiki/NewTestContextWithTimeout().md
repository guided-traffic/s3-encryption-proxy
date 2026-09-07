# NewTestContextWithTimeout()

> God node · 65 connections · `test/integration/minio_test_helper.go`

## Connections by Relation

### calls
- [[TestEncEveryPutPathStoresCiphertext()]] `EXTRACTED`
- [[createMinIOClient()]] `EXTRACTED`
- [[TestMpuThreePartRoundTrip()]] `INFERRED`
- [[createProxyClient()]] `EXTRACTED`
- [[TestEncAWSChunkedFramingStoresCiphertext()]] `EXTRACTED`
- [[TestMpuPartsUploadedOutOfOrder()]] `INFERRED`
- [[TestHdrEntityHeadersSurvivePutGetAndHead()]] `INFERRED`
- [[TestDelBatchDeleteRemovesLargeEncryptedObjects()]] `EXTRACTED`
- [[TestMpuCompleteWithPartsOutOfOrder()]] `INFERRED`
- [[TestEncCopyObjectNeverStoresPlaintext()]] `EXTRACTED`
- [[TestEncTamperedCiphertextIsRejected()]] `EXTRACTED`
- [[TestEncStreamedPutWithoutContentLengthStoresCiphertext()]] `EXTRACTED`
- [[TestEncStoredHMACEnforcement()]] `EXTRACTED`
- [[TestRangeReadsOnEncryptedObjects()]] `EXTRACTED`
- [[TestBackendErrorsKeepTheirStatusAndCode()]] `EXTRACTED`
- [[TestMpuAbortRemovesTheUpload()]] `INFERRED`
- [[TestEncClientDrivenMultipartStoresCiphertext()]] `EXTRACTED`
- [[TestEncUploadPartCopyNeverStoresPlaintext()]] `EXTRACTED`
- [[TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext()]] `EXTRACTED`
- [[TestHdrEncryptionMetadataIsNeverVisibleToTheClient()]] `INFERRED`

### contains
- [[minio_test_helper.go]] `EXTRACTED`

### references
- [[TestContext (MinIO plus proxy clients)]] `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*