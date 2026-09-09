# Object GET Handler Tests

> 107 nodes · cohesion 0.06

## Key Concepts

- **ObjGetnewHandler()** (44 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **getobject_coverage_test.go** (39 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetdo()** (39 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetpayload()** (32 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetgetOutput()** (23 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **object/rangeread_coverage_test.go** (23 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetstore()** (21 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **ObjGetparseError()** (19 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **object_test.go** (19 connections) — `internal/proxy/handlers/object/object_test.go`
- **newResponseTestHandler()** (19 connections) — `internal/proxy/handlers/object/object_test.go`
- **ObjGetrangeRequest()** (19 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **ObjGetdigest()** (15 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **newEncryptingTestHandler()** (12 connections) — `internal/proxy/handlers/object/object_test.go`
- **TestObjGetGetObjectCorruptGCMCiphertextIsNotServed()** (9 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetRangeBackendIgnoredRangeStillAnswers206()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeGCMRejectsMultipleAndMalformedRanges()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeGCMSuffixAndOpenEnded()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeGCMTakesTheWindowFromAFullDecryption()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetRangeGCMUnsatisfiableIs416()** (9 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **TestObjGetGetObjectBackendBodyCloseFailureStillDelivers()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectReturnsPlaintext()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectTamperedCTRIsServedDespiteStrictMode()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetGetObjectTamperedGCMNeverReachesTheClient()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **TestObjGetHeadObjectReportsPlaintextContentLength()** (8 connections) — `internal/proxy/handlers/object/getobject_coverage_test.go`
- **assertNoChecksumHeaders()** (8 connections) — `internal/proxy/handlers/object/object_test.go`
- *... and 82 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (75 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (5 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (3 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [GetObject Backend Method](GetObject_Backend_Method.md) (1 shared connections)
- [Ciphertext Size Arithmetic](Ciphertext_Size_Arithmetic.md) (1 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/getobject_coverage_test.go`
- `internal/proxy/handlers/object/object_test.go`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/range_test.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 320 (74%)
- INFERRED: 112 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*