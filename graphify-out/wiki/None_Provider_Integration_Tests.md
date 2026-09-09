# None Provider Integration Tests

> 12 nodes · cohesion 0.33

## Key Concepts

- **StartNoneProviderProxyInstance()** (11 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **none_provider_test.go** (9 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **ProxyTestInstance** (8 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **IsNoneProviderActive()** (8 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestNoneProvider_PurePassthrough()** (8 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestNoneProviderMultipleObjects()** (8 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestNoneProviderWithMinIO()** (8 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **context.CancelFunc** (5 connections)
- **.Stop()** (4 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestConfigValidationWithNoneProvider()** (2 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestHTTPHandlersWithMockData()** (2 connections) — `test/integration/encryption-modes/none_provider_test.go`
- **TestProviderTypesSupported()** (2 connections) — `test/integration/encryption-modes/none_provider_test.go`

## Relationships

- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (13 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (8 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (2 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (1 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (1 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Config File Loading](Config_File_Loading.md) (1 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (1 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (1 shared connections)

## Source Files

- `test/integration/encryption-modes/none_provider_test.go`

## Audit Trail

- EXTRACTED: 40 (75%)
- INFERRED: 13 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*