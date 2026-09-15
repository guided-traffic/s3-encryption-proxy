# EnsureMinIOAndProxyAvailable()

> God node · 122 connections · `test/integration/minio_test_helper.go`

**Community:** [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md)

## Connections by Relation

### calls
- TestEncEveryPutPathStoresCiphertext() `EXTRACTED`
- TestEncAWSChunkedFramingStoresCiphertext() `EXTRACTED`
- TestSegmentChainRefusesTamperedBytes() `EXTRACTED`
- TestEncClientDrivenMultipartStoresCiphertext() `EXTRACTED`
- TestMpuThreePartRoundTrip() `EXTRACTED`
- TestComprehensiveMultipartUpload() `EXTRACTED`
- TestEncClientMetadataInsideThePrefixIsRefused() `EXTRACTED`
- TestMpuPartsUploadedOutOfOrder() `EXTRACTED`
- TestComprehensiveSinglePartUpload() `EXTRACTED`
- TestDelBatchDeleteThreeExistingKeys() `EXTRACTED`
- TestEncCopyObjectNeverStoresPlaintext() `EXTRACTED`
- TestMpuHeldPartResentAtStreamingSize() `EXTRACTED`
- TestSinglePartUploadCornerCases() `EXTRACTED`
- TestDelBatchDeleteIntegrityHeaderIsEnforced() `EXTRACTED`
- TestDelBatchDeleteKeysNeedingXMLEscaping() `EXTRACTED`
- TestDelBatchDeleteMixOfExistingAndMissingKeys() `EXTRACTED`
- TestDelBatchDeleteQuietMode() `EXTRACTED`
- TestEncStreamedPutWithoutContentLengthStoresCiphertext() `EXTRACTED`
- TestEncUploadPartCopyNeverStoresPlaintext() `EXTRACTED`
- lstNewRefFixture() `EXTRACTED`
- *…and 100 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- minio_test_helper.go `EXTRACTED`

### references
- testing.T `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*