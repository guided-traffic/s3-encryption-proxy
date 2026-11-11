# S3 Methods: Conditional Requests Test

> 10 nodes · cohesion 0.33

## Key Concepts

- **TestCondGetAndHeadPreconditions()** (11 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **TestCondETagRoundTripIsSelfConsistent()** (10 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condGet()** (9 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condHead()** (8 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPutObject()** (6 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPrecondition** (4 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condOutcome** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condCodeOf()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condPayload()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`
- **condStatusOf()** (3 connections) — `test/integration/s3-methods/conditional_requests_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (4 shared connections)
- [Tampering Harness](Tampering_Harness.md) (3 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (2 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (2 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (2 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/conditional_requests_test.go`

## Audit Trail

- EXTRACTED: 45 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*