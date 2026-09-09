# AES and RSA Provider Tests

> 28 nodes · cohesion 0.27

## Key Concepts

- **CreateTestBucket()** (31 connections) — `test/integration/minio_test_helper.go`
- **CreateMinIOClient()** (27 connections) — `test/integration/minio_test_helper.go`
- **EnsureMinIOAvailable()** (15 connections) — `test/integration/minio_test_helper.go`
- **StartRSAProviderProxyInstance()** (13 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **AssertDataIsEncryptedBasic()** (13 connections) — `test/integration/encryption_validation_helper.go`
- **StartAESProviderProxyInstance()** (12 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestRSAProvider_MetadataHandling()** (12 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **TestRSAProviderWithMinIO()** (12 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **TestRSAProvider_LargeFile()** (11 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **TestAESProvider_LargeFile()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProvider_MetadataHandling()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderWithMinIO()** (10 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **IsRSAProviderActive()** (10 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **IsAESProviderActive()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **TestAESProviderMultipleObjects()** (9 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **AESProxyTestInstance** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **RSAProxyTestInstance** (8 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **aes_provider_test.go** (8 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **rsa_provider_test.go** (8 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **TestRSAProvider_KeyRotationCompatibility()** (8 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **TestRSAProviderMultipleObjects()** (8 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **assertDataHashesEqual()** (7 connections) — `test/integration/encryption-modes/test_helpers.go`
- **.Stop()** (6 connections) — `test/integration/encryption-modes/rsa_provider_test.go`
- **assertDataHashesNotEqual()** (6 connections) — `test/integration/encryption-modes/test_helpers.go`
- **.Stop()** (5 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- *... and 3 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (19 shared connections)
- [None Provider Integration Tests](None_Provider_Integration_Tests.md) (13 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (10 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (8 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (5 shared connections)
- [Ciphertext Entropy Validation](Ciphertext_Entropy_Validation.md) (3 shared connections)
- [Comprehensive Multipart Tests](Comprehensive_Multipart_Tests.md) (3 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (2 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (2 shared connections)
- [Config File Loading](Config_File_Loading.md) (2 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (2 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (2 shared connections)

## Source Files

- `test/integration/encryption-modes/aes_provider_test.go`
- `test/integration/encryption-modes/rsa_provider_test.go`
- `test/integration/encryption-modes/test_helpers.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 120 (65%)
- INFERRED: 64 (35%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*