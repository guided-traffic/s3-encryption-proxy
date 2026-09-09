# DeleteObjects Batch Tests

> 30 nodes · cohesion 0.24

## Key Concepts

- **delete_objects_batch_test.go** (29 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelNewMinIOBucket()** (15 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelPostDelete()** (13 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteThreeExistingKeys()** (13 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **DelPutKeys()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
- **TestDelBatchDeleteIntegrityHeaderNotEnforced()** (12 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
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

- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (20 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (19 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (6 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (5 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (4 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (3 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (1 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/delete_objects_batch_test.go`

## Audit Trail

- EXTRACTED: 164 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*