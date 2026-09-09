# CTR Single-Part Tests

> 11 nodes · cohesion 0.49

## Key Concepts

- **TestComprehensiveSinglePartCTRUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **comprehensive_singlepart_ctr_test.go** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **downloadCTRSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **uploadCTRSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **TestSinglePartCTRUploadCornerCases()** (9 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **TestSinglePartCTRUploadVsMultipart()** (9 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **cleanupCTRSinglePartTestFile()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **generateCTRSinglePartTestData()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **verifyCTRSinglePartDataIntegrity()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **verifyCTRSinglePartEncryptionMetadata()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`
- **verifyCTRSinglePartFileInMinIO()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (10 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (6 shared connections)
- [Single-Part Throughput Tests](Single-Part_Throughput_Tests.md) (6 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (5 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (3 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (3 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_singlepart_ctr_test.go`

## Audit Trail

- EXTRACTED: 55 (90%)
- INFERRED: 6 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*