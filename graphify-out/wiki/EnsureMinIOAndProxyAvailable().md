# EnsureMinIOAndProxyAvailable()

> God node · 83 connections · `test/integration/minio_test_helper.go`

## Connections by Relation

### calls
- [[TestEncEveryPutPathStoresCiphertext()]] `INFERRED`
- [[TestMpuThreePartRoundTrip()]] `INFERRED`
- [[TestEncAWSChunkedFramingStoresCiphertext()]] `INFERRED`
- [[TestMpuPartsUploadedOutOfOrder()]] `INFERRED`
- [[TestHdrEntityHeadersSurvivePutGetAndHead()]] `INFERRED`
- [[TestDelBatchDeleteRemovesLargeEncryptedObjects()]] `INFERRED`
- [[TestMpuCompleteWithPartsOutOfOrder()]] `INFERRED`
- [[TestEncCopyObjectNeverStoresPlaintext()]] `INFERRED`
- [[TestEncTamperedCiphertextIsRejected()]] `INFERRED`
- [[TestEncStreamedPutWithoutContentLengthStoresCiphertext()]] `INFERRED`
- [[TestEncStoredHMACEnforcement()]] `INFERRED`
- [[TestRangeReadsOnEncryptedObjects()]] `EXTRACTED`
- [[TestBackendErrorsKeepTheirStatusAndCode()]] `INFERRED`
- [[TestMpuAbortRemovesTheUpload()]] `INFERRED`
- [[TestEncClientDrivenMultipartStoresCiphertext()]] `INFERRED`
- [[TestEncUploadPartCopyNeverStoresPlaintext()]] `INFERRED`
- [[TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext()]] `INFERRED`
- [[TestHdrEncryptionMetadataIsNeverVisibleToTheClient()]] `INFERRED`
- [[TestHdrStorageHeadersAreAcceptedAndSilentlyDropped()]] `INFERRED`
- [[TestComprehensiveMultipartUpload()]] `EXTRACTED`

### contains
- [[minio_test_helper.go]] `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*