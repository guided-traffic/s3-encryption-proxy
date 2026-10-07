# MockS3Backend Multipart Operations

> 34 nodes · cohesion 0.09

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectOutput** (10 connections)
- **optionalString()** (9 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput** (7 connections)
- **ConditionalHeaders** (7 connections) — `internal/proxy/handlers/object/storage_headers.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadInput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectInput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectInput** (5 connections)
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.HeadObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectOutput** (4 connections)
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.HeadObject()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.HeadObject()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (19 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (8 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (7 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (4 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (4 shared connections)
- [MockS3Backend Listing and Upload Stubs](MockS3Backend_Listing_and_Upload_Stubs.md) (4 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (2 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (1 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/storage_headers.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 102 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*