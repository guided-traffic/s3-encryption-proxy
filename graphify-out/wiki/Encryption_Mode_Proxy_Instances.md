# Encryption Mode Proxy Instances

> 44 nodes · cohesion 0.15

## Key Concepts

- **CreateTestBucket()** (28 connections) — `test/integration/minio_test_helper.go`
- **CreateMinIOClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **StartAESProviderProxyInstance()** (14 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **EnsureMinIOAvailable()** (14 connections) — `test/integration/minio_test_helper.go`
- **TestExitProvider_ReadsBackAnEncryptedObject()** (13 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **exit_provider_test.go** (13 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProvider_ReadsBackAMultipartObject()** (12 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ClientDrivenPartIsNeverHeldWhole()** (11 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **StartExitProviderProxyInstanceTuned()** (11 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **AssertDataIsEncryptedBasic()** (11 connections) — `test/integration/encryption_validation_helper.go`
- **TestAESProvider_LargeFile()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProvider_MetadataHandling()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderWithMinIO()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **exit_provider_readback_test.go** (10 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ClientDrivenMultipart()** (10 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **StartExitProviderProxyInstance()** (10 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **ExitProxyTestInstance** (9 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **IsAESProviderActive()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderMultipleObjects()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **assertStoredPlaintext()** (9 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **assertDataHashesEqual()** (9 connections) — `test/integration/encryption-modes/test_helpers.go`
- **AESProxyTestInstance** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **aes_provider_test.go** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **IsExitProviderActive()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProvider_PurePassthrough()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- *... and 19 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (30 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (23 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (9 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (6 shared connections)
- [Encryption Validation Helper](Encryption_Validation_Helper.md) (3 shared connections)
- [Server](Server.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (2 shared connections)
- [Conditional Requests](Conditional_Requests.md) (2 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)
- [Integration Corpus Seed and Budget](Integration_Corpus_Seed_and_Budget.md) (1 shared connections)

## Source Files

- `test/integration/encryption-modes/aes_provider_test.go`
- `test/integration/encryption-modes/exit_provider_readback_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/encryption-modes/test_helpers.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 176 (75%)
- INFERRED: 60 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*