# S3 Method Error Mapping Tests

> 9 nodes · cohesion 0.47

## Key Concepts

- **TestBackendErrorsKeepTheirStatusAndCode()** (8 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestLstListObjectsMissingBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestVbRefusedCopiesLeaveNothingBehind()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **apiCodeOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **httpStatusOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **s3-methods/error_mapping_test.go** (6 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestConditionalRequestErrors()** (5 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **errorsAs()** (4 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **apiMessageOf()** (3 connections) — `test/integration/s3-methods/error_mapping_test.go`

## Relationships

- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (5 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (3 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (3 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (3 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (2 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (1 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/error_mapping_test.go`
- `test/integration/s3-methods/listobjects_conformance_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`

## Audit Trail

- EXTRACTED: 31 (79%)
- INFERRED: 8 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*