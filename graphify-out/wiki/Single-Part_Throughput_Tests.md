# Single-Part Throughput Tests

> 17 nodes · cohesion 0.32

## Key Concepts

- **comprehensive_singlepart_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadCornerCases()** (11 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **calculateThroughput()** (8 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **cleanupSinglePartTestFile()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFileWithMetrics()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **downloadSinglePartFileWithMetrics()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **formatDataSize()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **formatThroughput()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **generateSinglePartTestData()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartDataIntegrity()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartEncryptionMetadata()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartFileInMinIO()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **PerformanceMetrics** (4 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (12 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (10 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (7 shared connections)
- [CTR Single-Part Tests](CTR_Single-Part_Tests.md) (6 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (3 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`

## Audit Trail

- EXTRACTED: 83 (93%)
- INFERRED: 6 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*