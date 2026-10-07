# Object Dispatch Coverage Tests

> 26 nodes · cohesion 0.24

## Key Concepts

- **ObjMiscnewHandler()** (48 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **dispatch_coverage_test.go** (26 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdo()** (19 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscdoFunc()** (17 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **net/http/httptest.ResponseRecorder** (16 connections)
- **ObjMiscassertNotImplemented()** (14 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **ObjMiscsealed()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleDispatchesEachMethodToItsOwnBackendCall()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesAnObjectThisProxyDidNotWrite()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRoutesTaggingToTheTaggingHandler()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleUnsupportedMethodIsRefusedNotSilently200()** (6 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscACLHandlerDirectEntryPoint()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleACLBeatsTaggingWhenBothArePresent()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesGetObjectAttributesInsteadOfReturningBytes()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRefusesSubResourcesThatReachTheBaseOperation()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRoutesACLToTheACLHandler()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscHandleRoutesACLWithAValue()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscObjectSubResourcesRefusedOnUnsupportedVerbs()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscObjectTorrentIsRefusedNotPassedThroughUndecrypted()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscPassthroughWrappersTolerateMissingMuxVars()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscSubHandlerAccessorsReturnTheWiredInstances()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscTaggingHandlerDirectEntryPoint()** (5 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscRetentionAndLegalHoldArePassthrough()** (4 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **TestObjMiscVersionIDTravelsBothWaysOnDelete()** (4 connections) — `internal/proxy/handlers/object/metadata_coverage_test.go`
- **Handler** (3 connections)
- *... and 1 more nodes in this community*

## Relationships

- [DeleteObjects Coverage Tests](DeleteObjects_Coverage_Tests.md) (34 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (20 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (13 shared connections)
- [ListBuckets Coverage Tests](ListBuckets_Coverage_Tests.md) (3 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (3 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (1 shared connections)
- [Object Broken Reader Stub](Object_Broken_Reader_Stub.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/object/metadata_coverage_test.go`

## Audit Trail

- EXTRACTED: 122 (75%)
- INFERRED: 40 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*