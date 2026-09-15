# ObjGetdo()

> God node · 67 connections · `internal/proxy/handlers/object/getobject_coverage_test.go`

**Community:** [Object GET Coverage Tests](Object_GET_Coverage_Tests.md)

## Connections by Relation

### calls
- TestObjTagEveryObjectVerbAnswersTheMarker() `INFERRED`
- TestObjGetGetObjectUnderTheExitProviderDecidesPerObject() `EXTRACTED`
- TestObjIntAMidStreamFaultIsLoggedAndCounted() `INFERRED`
- TestObjIntARangedFaultIsLoggedAndCounted() `INFERRED`
- TestObjGetRangeExitProviderRefusesAnObjectItCannotOpen() `INFERRED`
- TestObjGetGetObjectForgedExitFingerprintIsNotServed() `EXTRACTED`
- TestObjGetGetObjectUndecryptableMetadata() `EXTRACTED`
- TestObjGetHeadObjectRefusesWhatItCannotSize() `EXTRACTED`
- TestObjGetRangeExitProviderCostsOneHeadForASuffixRange() `INFERRED`
- TestObjGetRangeExitProviderStillDecryptsASealedObject() `INFERRED`
- TestObjGetGetObjectTamperedObjectIsNotDelivered() `EXTRACTED`
- TestObjGetServesTheSealedChecksum() `EXTRACTED`
- TestObjCrcAWriteAndAReadAgreeOnTheChecksum() `INFERRED`
- TestObjIntARefusalIsCountedBeforeTheResponse() `INFERRED`
- TestObjGetRangeFaultInALaterSegmentStopsTheBody() `INFERRED`
- TestObjGetRangeReturnsThePlaintextWindow() `INFERRED`
- TestObjGetRangeSuffixAndOpenEndedResolveAgainstTheHead() `INFERRED`
- TestObjGetGetObjectBackendBodyCloseFailureStillDelivers() `EXTRACTED`
- TestObjGetGetObjectReturnsPlaintext() `EXTRACTED`
- TestObjGetHeadHonoursResponseOverrides() `EXTRACTED`
- *…and 43 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- getobject_coverage_test.go `EXTRACTED`

### references
- net/http.Request `EXTRACTED`
- net/http/httptest.ResponseRecorder `EXTRACTED`
- Handler `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*