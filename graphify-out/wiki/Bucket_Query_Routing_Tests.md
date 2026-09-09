# Bucket Query Routing Tests

> 5 nodes · cohesion 0.50

## Key Concepts

- **.handleBucket()** (4 connections) — `internal/proxy/handlers/bucket/routing_test.go`
- **TestBucketListingWithQueryParameters()** (4 connections) — `internal/proxy/handlers/bucket/routing_test.go`
- **testTrackingHandler** (3 connections) — `internal/proxy/handlers/bucket/routing_test.go`
- **routing_test.go** (2 connections) — `internal/proxy/handlers/bucket/routing_test.go`
- **Handler** (1 connections)

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (1 shared connections)
- [Bucket Location and Logging Tests](Bucket_Location_and_Logging_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/routing_test.go`

## Audit Trail

- EXTRACTED: 8 (89%)
- INFERRED: 1 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*