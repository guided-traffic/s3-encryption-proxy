# Object Header Conformance

> 18 nodes · cohesion 0.34

## Key Concepts

- **net/http.Header** (34 connections)
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

- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (14 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (8 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (5 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (4 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (3 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (2 shared connections)
- [Health Handler](Health_Handler.md) (2 shared connections)
- [Monitoring Server](Monitoring_Server.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (2 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (2 shared connections)

## Source Files

- `test/integration/s3-methods/object_headers_conformance_test.go`

## Audit Trail

- EXTRACTED: 122 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*