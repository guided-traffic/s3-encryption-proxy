# Provider Mode Integration Tests

> 28 nodes · cohesion 0.22

## Key Concepts

- **CreateTestBucket()** (27 connections) — `test/integration/minio_test_helper.go`
- **CreateMinIOClient()** (23 connections) — `test/integration/minio_test_helper.go`
- **StartAESProviderProxyInstance()** (14 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **StartExitProviderProxyInstance()** (14 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **EnsureMinIOAvailable()** (13 connections) — `test/integration/minio_test_helper.go`
- **exit_provider_test.go** (12 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestAESProvider_LargeFile()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProvider_MetadataHandling()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderWithMinIO()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **AssertDataIsEncryptedBasic()** (10 connections) — `test/integration/encryption_validation_helper.go`
- **IsAESProviderActive()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderMultipleObjects()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **AESProxyTestInstance** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **ExitProxyTestInstance** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **aes_provider_test.go** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **IsExitProviderActive()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProvider_PurePassthrough()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProviderMultipleObjects()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestExitProviderWithMinIO()** (8 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **loadTestConfig()** (7 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **.Stop()** (5 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **.Stop()** (4 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **context.CancelFunc** (4 connections)
- **exitTestConfig()** (4 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestConfigValidationWithExitProvider()** (4 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- *... and 3 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (18 shared connections)
- [Exit Provider Readback Tests](Exit_Provider_Readback_Tests.md) (15 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (10 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (9 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (6 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (6 shared connections)
- [Encryption Validation Helper](Encryption_Validation_Helper.md) (3 shared connections)
- [360-Degree Multipart Tests](360-Degree_Multipart_Tests.md) (3 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (2 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (2 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (2 shared connections)

## Source Files

- `test/integration/encryption-modes/aes_provider_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 121 (71%)
- INFERRED: 50 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*