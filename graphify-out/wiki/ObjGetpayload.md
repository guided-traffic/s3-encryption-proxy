# ObjGetpayload()

> God node · 60 connections · `internal/proxy/handlers/object/getobject_coverage_test.go`

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
- TestObjIntAClientDisconnectIsNotAnIntegrityFailure() `INFERRED`
- TestObjIntARefusalIsCountedBeforeTheResponse() `INFERRED`
- TestObjGetRangeFaultInALaterSegmentStopsTheBody() `INFERRED`
- TestObjGetRangeReturnsThePlaintextWindow() `INFERRED`
- TestObjGetRangeSuffixAndOpenEndedResolveAgainstTheHead() `INFERRED`
- TestObjGetGetObjectBackendBodyCloseFailureStillDelivers() `EXTRACTED`
- TestObjGetGetObjectReturnsPlaintext() `EXTRACTED`
- *…and 39 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- getobject_coverage_test.go `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*