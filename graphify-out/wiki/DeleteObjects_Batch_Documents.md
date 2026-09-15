# DeleteObjects Batch Documents

> 30 nodes · cohesion 0.24

## Key Concepts

- **delete_objects_batch_test.go** (29 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelNewMinIOBucket()** (15 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelPostDelete()** (13 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteThreeExistingKeys()** (13 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelPutKeys()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteIntegrityHeaderIsEnforced()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteKeysNeedingXMLEscaping()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteMixOfExistingAndMissingKeys()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteQuietMode()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelParseResult()** (11 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteRemovesLargeEncryptedObjects()** (11 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelBuildDoc()** (10 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelObjectExists()** (10 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteResponseDocumentShape()** (10 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelKeySet()** (9 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteKeyLimit()** (9 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteThroughTheSDK()** (8 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelDeletedKeys()** (7 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelParseError()** (7 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelPostDeleteRaw()** (7 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteMalformedDocuments()** (7 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelResponse** (6 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelResultDoc** (6 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelHasEncryptionMetadata()** (5 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelCleanupBucket()** (4 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- *... and 5 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (19 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (10 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (10 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (6 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (5 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (5 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (3 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/delete_objects_batch_test.go`

## Audit Trail

- EXTRACTED: 164 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*