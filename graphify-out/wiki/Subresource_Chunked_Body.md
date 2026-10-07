# Subresource Chunked Body

> 13 nodes · cohesion 0.32

## Key Concepts

- **subresource_chunked_body_test.go** (10 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **BktChunkedHandler()** (8 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **BktChunkedRequest()** (6 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **TestBktChunkedBodyWithACorrectTrailerIsApplied()** (6 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **TestBktChunkedBodyWithAWrongTrailerIsRefused()** (5 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **bktChunkedTarget** (4 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **net/http.HandlerFunc** (4 connections)
- **bktChunkedTargets()** (4 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **TestBktChunkedBodyWithAMalformedTrailerIsRefused()** (4 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **TestBktCreateBucketVerifiesAnEmptyBodyDigest()** (4 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **BktChunkedBody()** (2 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **bktChunkedOutput()** (2 connections) — `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`
- **Handler** (2 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Object Dispatch Coverage Tests](Object_Dispatch_Coverage_Tests.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (1 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_chunked_body_test.go`

## Audit Trail

- EXTRACTED: 34 (94%)
- INFERRED: 2 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*