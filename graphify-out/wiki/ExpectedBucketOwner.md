# ExpectedBucketOwner()

> God node · 60 connections · `internal/proxy/request/bucketowner.go`

**Community:** [ACL, CORS and Lifecycle Handlers](ACL,_CORS_and_Lifecycle_Handlers.md)

## Connections by Relation

### calls
- .handleGetObjectRange() `EXTRACTED`
- .listObjectsV1() `EXTRACTED`
- .listObjectsV2() `EXTRACTED`
- .Handle() `EXTRACTED`
- .putObjectAutoMultipart() `EXTRACTED`
- .handleHeadObject() `EXTRACTED`
- .putObjectSegmented() `EXTRACTED`
- .servePerObject() `EXTRACTED`
- .fetchObjectTail() `EXTRACTED`
- .passThroughRange() `EXTRACTED`
- .serveWholeObject() `EXTRACTED`
- .listPassThroughParts() `EXTRACTED`
- .storePassThroughPart() `EXTRACTED`
- .handleGetTagging() `EXTRACTED`
- .handlePutTagging() `EXTRACTED`
- .handleObjectLegalHold() `EXTRACTED`
- .handleObjectRetention() `EXTRACTED`
- .abortUpload() `EXTRACTED`
- .Handle() `EXTRACTED`
- .HandleListMultipartUploads() `EXTRACTED`
- *…and 37 more `calls` connection(s) not listed (lowest-degree first to go)*

### contains
- bucketowner.go `EXTRACTED`

### references
- net/http.Request `EXTRACTED`
- The Ownership Precondition Set in Every s3.*Input Literal `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*