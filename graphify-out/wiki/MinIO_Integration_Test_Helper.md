# MinIO Integration Test Helper

> 22 nodes · cohesion 0.15

## Key Concepts

- **minio_test_helper.go** (31 connections) — `test/integration/minio_test_helper.go`
- **createMinIOClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **NewS3Client()** (7 connections) — `test/integration/minio_test_helper.go`
- **CreateProxyClientWithEndpoint()** (6 connections) — `test/integration/minio_test_helper.go`
- **tlsHTTPClient()** (6 connections) — `test/integration/minio_test_helper.go`
- **WaitForHealthCheck()** (6 connections) — `test/integration/minio_test_helper.go`
- **NewProxyTLSClient()** (5 connections) — `test/integration/minio_test_helper.go`
- **SkipIfMinIONotAvailable()** (5 connections) — `test/integration/minio_test_helper.go`
- **SkipIfProxyNotAvailable()** (4 connections) — `test/integration/minio_test_helper.go`
- **net/http.Client** (3 connections)
- **CleanupTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **CompareObjectData()** (3 connections) — `test/integration/minio_test_helper.go`
- **contains()** (3 connections) — `test/integration/minio_test_helper.go`
- **IsAlreadyExistsError()** (3 connections) — `test/integration/minio_test_helper.go`
- **testCAPool()** (3 connections) — `test/integration/minio_test_helper.go`
- **findInString()** (2 connections) — `test/integration/minio_test_helper.go`
- **IsMinIOAvailable()** (2 connections) — `test/integration/minio_test_helper.go`
- **IsProxyAvailable()** (2 connections) — `test/integration/minio_test_helper.go`
- **ProxyIsTLS()** (2 connections) — `test/integration/minio_test_helper.go`
- **crypto/x509.CertPool** (1 connections)
- **envOr()** (1 connections) — `test/integration/minio_test_helper.go`

## Relationships

- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (10 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (9 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (8 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (8 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (5 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (3 shared connections)
- [None Provider Integration Tests](None_Provider_Integration_Tests.md) (2 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 74 (92%)
- INFERRED: 6 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*