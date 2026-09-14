# MinIO Test Helper

> 20 nodes · cohesion 0.16

## Key Concepts

- **minio_test_helper.go** (31 connections) — `test/integration/minio_test_helper.go`
- **createMinIOClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **NewS3Client()** (7 connections) — `test/integration/minio_test_helper.go`
- **tlsHTTPClient()** (6 connections) — `test/integration/minio_test_helper.go`
- **CreateProxyClientWithEndpoint()** (5 connections) — `test/integration/minio_test_helper.go`
- **SkipIfMinIONotAvailable()** (5 connections) — `test/integration/minio_test_helper.go`
- **WaitForHealthCheck()** (5 connections) — `test/integration/minio_test_helper.go`
- **SkipIfProxyNotAvailable()** (4 connections) — `test/integration/minio_test_helper.go`
- **CleanupTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **CompareObjectData()** (3 connections) — `test/integration/minio_test_helper.go`
- **contains()** (3 connections) — `test/integration/minio_test_helper.go`
- **IsAlreadyExistsError()** (3 connections) — `test/integration/minio_test_helper.go`
- **testCAPool()** (3 connections) — `test/integration/minio_test_helper.go`
- **crypto/x509.CertPool** (2 connections)
- **findInString()** (2 connections) — `test/integration/minio_test_helper.go`
- **IsMinIOAvailable()** (2 connections) — `test/integration/minio_test_helper.go`
- **IsProxyAvailable()** (2 connections) — `test/integration/minio_test_helper.go`
- **ProxyIsTLS()** (2 connections) — `test/integration/minio_test_helper.go`
- **envOr()** (1 connections) — `test/integration/minio_test_helper.go`

## Relationships

- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (10 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (10 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (8 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (5 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (3 shared connections)
- [Passthrough Operation Tests](Passthrough_Operation_Tests.md) (3 shared connections)
- [Performance Harness](Performance_Harness.md) (2 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (2 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 70 (95%)
- INFERRED: 4 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*