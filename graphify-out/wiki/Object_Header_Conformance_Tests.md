# Object Header Conformance Tests

> 18 nodes · cohesion 0.34

## Key Concepts

- **net/http.Header** (33 connections)
- **object_headers_conformance_test.go** (17 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrNewDirectBucket()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrGetHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrHeadHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrHeadReturnsTheSameHeaderSetAsGet()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrUserMetadataRoundTripsLikeTheBackend()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEncryptionMetadataIsNeverVisibleToTheClient()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEntityHeadersSurvivePutGetAndHead()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrETagIsPresentAndStableAcrossRepeatedHeads()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrPutWithEntityHeaders()** (9 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrObjectHeaderNames()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrCaptureResponseHeaders()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrUserMetadata()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.Options** (4 connections)
- **HdrCaptureResponseBody()** (3 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrCleanupBucket()** (3 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrIsObjectHeader()** (2 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`

## Relationships

- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (14 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (9 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (8 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (5 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (4 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (3 shared connections)
- [Bucket Handler Test Fakes](Bucket_Handler_Test_Fakes.md) (2 shared connections)
- [Health Handler Tests](Health_Handler_Tests.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (2 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (2 shared connections)

## Source Files

- `test/integration/s3-methods/object_headers_conformance_test.go`

## Audit Trail

- EXTRACTED: 121 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*