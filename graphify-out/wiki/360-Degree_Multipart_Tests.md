# 360-Degree Multipart Tests

> 20 nodes · cohesion 0.20

## Key Concepts

- **comprehensive_multipart_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveMultipartUpload()** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestStreamingMultipartUpload()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestMultipartUploadCorruption()** (9 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **verifyDataIntegrityStreaming()** (9 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **uploadLargeFileStreaming()** (7 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **StreamingReader** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadLargeFile()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **uploadLargeFileMultipart()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **verifyDataIntegrity()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **verifyFileInMinIO()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **cleanupTestFile()** (5 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **generateLargeFileTestData()** (5 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **NewStreamingReader()** (5 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **GenerateLoremIpsumPattern()** (4 connections) — `test/integration/encryption_validation_helper.go`
- **GenerateLoremIpsumData()** (3 connections) — `test/integration/encryption_validation_helper.go`
- **.GetOriginalHash()** (2 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **.Read()** (2 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **max()** (1 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **min()** (1 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`

## Relationships

- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (17 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (12 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (7 shared connections)
- [Encryption Validation Helper](Encryption_Validation_Helper.md) (5 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (3 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (3 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/encryption_validation_helper.go`

## Audit Trail

- EXTRACTED: 83 (98%)
- INFERRED: 2 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*