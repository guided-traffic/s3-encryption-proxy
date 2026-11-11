# DeleteObjects Conformance

> 30 nodes · cohesion 0.24

## Key Concepts

- **delete_objects_batch_test.go** (53 connections) — `test/integration/s3-methods/delete_objects_batch_test.go`
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

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (23 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (19 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (11 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (10 shared connections)
- [Tampering Harness](Tampering_Harness.md) (6 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (5 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (4 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (3 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)
- [Router and Middleware Setup](Router_and_Middleware_Setup.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/delete_objects_batch_test.go`

## Audit Trail

- EXTRACTED: 188 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*