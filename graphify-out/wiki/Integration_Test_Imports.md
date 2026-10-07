# Integration Test Imports

> 23 nodes · cohesion 0.15

## Key Concepts

- **sealed_checksum_test.go** (27 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksCheckWritePath()** (10 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksAssertServedChecksum()** (7 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestCksSuffixRangeLargerThanTheObject()** (6 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **github.com/guided-traffic/s3-encryption-proxy/test/integration.TestContext** (5 connections)
- **CksStored()** (5 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksStoredLength()** (5 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksAssertChecksumSealed()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksDelete()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksPayload()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestCksEveryWritePathSealsTheSameChecksum()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **go_pkg_context** (3 connections)
- **go_pkg_github_com_stretchr_testify_assert** (3 connections)
- **go_pkg_github_com_stretchr_testify_require** (3 connections)
- **CksExpected()** (3 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **go_pkg_bytes** (2 connections)
- **go_pkg_fmt** (2 connections)
- **go_pkg_github_com_guided_traffic_s3_encryption_proxy_test_integration** (2 connections)
- **go_pkg_io** (2 connections)
- **CksOffsets()** (2 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **go_pkg_encoding_base64** (1 connections)
- **go_pkg_encoding_binary** (1 connections)
- **go_pkg_hash_crc32** (1 connections)

## Relationships

- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (11 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (5 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Object Lock Imports](Object_Lock_Imports.md) (3 shared connections)

## Source Files

- `test/integration/s3-methods/sealed_checksum_test.go`

## Audit Trail

- EXTRACTED: 66 (97%)
- INFERRED: 2 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*