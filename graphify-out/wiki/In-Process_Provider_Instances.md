# In-Process Provider Instances

> 39 nodes · cohesion 0.16

## Key Concepts

- **CreateTestBucket()** (28 connections) — `test/integration/minio_test_helper.go`
- **CleanupTestBucket()** (24 connections) — `test/integration/minio_test_helper.go`
- **CreateMinIOClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **StartAESProviderProxyInstance()** (14 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestExitProvider_ReadsBackAnEncryptedObject()** (14 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **EnsureMinIOAvailable()** (14 connections) — `test/integration/minio_test_helper.go`
- **TestExitProvider_ReadsBackAMultipartObject()** (13 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ClientDrivenPartIsNeverHeldWhole()** (12 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestChunkedUploadDecoding()** (11 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestExitProvider_ClientDrivenMultipart()** (11 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **AssertDataIsEncryptedBasic()** (11 connections) — `test/integration/encryption_validation_helper.go`
- **IsAESProviderActive()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProvider_LargeFile()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProvider_MetadataHandling()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderWithMinIO()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **StartExitProviderProxyInstance()** (10 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **StartExitProviderProxyInstanceTuned()** (10 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **ExitProxyTestInstance** (9 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestAESProviderMultipleObjects()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **assertStoredPlaintext()** (9 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **IsExitProviderActive()** (9 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **assertDataHashesEqual()** (9 connections) — `test/integration/encryption-modes/test_helpers.go`
- **AESProxyTestInstance** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestExitProvider_PurePassthrough()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProviderMultipleObjects()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- *... and 14 more nodes in this community*

## Relationships

- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (32 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (32 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (29 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (6 shared connections)
- [S3 Methods: Conditional Requests Test](S3_Methods-_Conditional_Requests_Test.md) (4 shared connections)
- [Server and Listings](Server_and_Listings.md) (2 shared connections)
- [Misc (15)](Misc_15.md) (2 shared connections)
- [Configuration Loading](Configuration_Loading.md) (2 shared connections)
- [Misc (41)](Misc_41.md) (2 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (2 shared connections)
- [Integration: Encryption Validation Helper](Integration-_Encryption_Validation_Helper.md) (2 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (2 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/encryption-modes/aes_provider_test.go`
- `test/integration/encryption-modes/exit_provider_readback_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/encryption-modes/test_helpers.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/streaming_test.go`

## Audit Trail

- EXTRACTED: 170 (69%)
- INFERRED: 75 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*