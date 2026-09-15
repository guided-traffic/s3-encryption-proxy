# Authentication Integration Tests

> 50 nodes · cohesion 0.08

## Key Concepts

- **TLSHTTPClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **auth_test.go** (13 connections) — `test/integration/authentication/auth_test.go`
- **SignHTTPRequestForS3WithCredentials()** (13 connections) — `test/integration/s3_signing_helper.go`
- **object_subresource_refusal_test.go** (11 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **subrefPutObject()** (10 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **subrefDigest()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefLegitimateParametersStillWork()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefMalformedPartNumberDoesNotOverwriteTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefSemicolonInTheQueryIsRefused()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefUnroutedSubResourcesDoNotDestroyTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestTbSlowDownloadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestTbSlowUploadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **SignHTTPRequestForS3()** (8 connections) — `test/integration/s3_signing_helper.go`
- **testRobustS3Authentication()** (7 connections) — `test/integration/authentication/auth_test.go`
- **hdrSignedPutQuery()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **subrefRawWithBody()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefPresignedGetIsNotRefusedAsASubResource()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestAWSV4SigningHelper()** (7 connections) — `test/integration/s3_signing_test.go`
- **testS3ClientAuthentication()** (6 connections) — `test/integration/authentication/auth_test.go`
- **bdocProxyGet()** (6 connections) — `test/integration/s3-methods/bucket_subresource_documents_test.go`
- **TestSubpassMalformedSubResourceDocumentIsMalformedXML()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **TestSubpassObjectTaggingRoundTrip()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **TestSubrefEncodedSemicolonIsNotRefused()** (6 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **SimpleTestContext** (5 connections) — `test/integration/authentication/auth_test.go`
- **sendWellFormedAuthHeader()** (5 connections) — `test/integration/authentication/auth_test.go`
- *... and 25 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (34 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (17 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (13 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (12 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (9 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (3 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (2 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (2 shared connections)
- [Range Conformance](Range_Conformance.md) (2 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (2 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (2 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)

## Source Files

- `test/integration/authentication/auth_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/bucket_subresource_documents_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`
- `test/integration/s3-methods/object_subresource_passthrough_test.go`
- `test/integration/s3-methods/object_subresource_refusal_test.go`
- `test/integration/s3-methods/transfer_budget_test.go`
- `test/integration/s3_signing_helper.go`
- `test/integration/s3_signing_test.go`

## Audit Trail

- EXTRACTED: 188 (92%)
- INFERRED: 16 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*