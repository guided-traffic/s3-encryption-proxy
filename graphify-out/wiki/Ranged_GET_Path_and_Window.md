# Ranged GET Path and Window

> 30 nodes · cohesion 0.12

## Key Concepts

- **.handleGetObjectRange()** (21 connections) — `internal/proxy/handlers/object/range.go`
- **.writeRangeResponse()** (11 connections) — `internal/proxy/handlers/object/range.go`
- **range.go** (9 connections) — `internal/proxy/handlers/object/range.go`
- **parseByteRange()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **.passThroughRange()** (9 connections) — `internal/proxy/handlers/object/range.go`
- **provisionalWindow()** (7 connections) — `internal/proxy/handlers/object/range.go`
- **.headForRange()** (7 connections) — `internal/proxy/handlers/object/range.go`
- **The Ranged GET Path** (6 connections) — `docs/developer/request-paths.md`
- **Handler** (6 connections) — `internal/proxy/handlers/object/range.go`
- **.plaintextLength()** (6 connections) — `internal/proxy/handlers/object/range.go`
- **parseRangeSpec()** (5 connections) — `internal/proxy/handlers/object/range.go`
- **pinToHeadETag()** (5 connections) — `internal/proxy/handlers/object/range.go`
- **range_test.go** (5 connections) — `internal/proxy/handlers/object/range_test.go`
- **The Ranged-Read Window and Its Amplification Bound** (4 connections) — `docs/developer/storage-format.md`
- **contentRangeTotal()** (4 connections) — `internal/proxy/handlers/object/range.go`
- **byteRange** (4 connections) — `internal/proxy/handlers/object/range.go`
- **Which Range Headers Are Acted On Is Decided Twice** (3 connections) — `docs/developer/request-paths.md`
- **TestHandleGetObjectRange_TheBackendGetCarriesTheVersion()** (3 connections) — `internal/proxy/handlers/object/range_test.go`
- **TestParseByteRange()** (3 connections) — `internal/proxy/handlers/object/range_test.go`
- **TestParseByteRange_EmptyObject()** (3 connections) — `internal/proxy/handlers/object/range_test.go`
- **TestParseByteRange_Errors()** (3 connections) — `internal/proxy/handlers/object/range_test.go`
- **TestObjGetContentRangeTotal()** (3 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetParseByteRangeEdgeCases()** (3 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetParseRangeSpec()** (3 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **.contentRange()** (3 connections) — `internal/proxy/handlers/object/range.go`
- *... and 5 more nodes in this community*

## Relationships

- [Response Header Helpers](Response_Header_Helpers.md) (9 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (6 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (5 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (4 shared connections)
- [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (3 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)
- [Segmented GCM Range Reader](Segmented_GCM_Range_Reader.md) (2 shared connections)
- [Performance Baselines and Findings](Performance_Baselines_and_Findings.md) (2 shared connections)
- [Helpers](Helpers.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `docs/developer/storage-format.md`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 85 (82%)
- INFERRED: 19 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*