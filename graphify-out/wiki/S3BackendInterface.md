# S3BackendInterface

> God node · 83 connections · `internal/proxy/interfaces/s3_backend.go`

**Community:** [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md)

## Connections by Relation

### contains
- s3_backend.go `EXTRACTED`

### method
- .UploadPart() `EXTRACTED`
- .AbortMultipartUpload() `EXTRACTED`
- .CreateMultipartUpload() `EXTRACTED`
- .CompleteMultipartUpload() `EXTRACTED`
- .ListMultipartUploads() `EXTRACTED`
- .ListParts() `EXTRACTED`
- .GetBucketAcl() `EXTRACTED`
- .PutBucketAcl() `EXTRACTED`
- .GetBucketCors() `EXTRACTED`
- .PutBucketCors() `EXTRACTED`
- .DeleteBucketCors() `EXTRACTED`
- .GetBucketVersioning() `EXTRACTED`
- .PutBucketVersioning() `EXTRACTED`
- .GetBucketAccelerateConfiguration() `EXTRACTED`
- .GetBucketRequestPayment() `EXTRACTED`
- .GetBucketTagging() `EXTRACTED`
- .PutBucketTagging() `EXTRACTED`
- .DeleteBucketTagging() `EXTRACTED`
- .GetBucketNotificationConfiguration() `EXTRACTED`
- .PutBucketNotificationConfiguration() `EXTRACTED`
- *…and 32 more `method` connection(s) not listed (lowest-degree first to go)*

### references
- Handler `EXTRACTED`
- NewBaseSubResourceHandler() `EXTRACTED`
- Handler `EXTRACTED`
- BktnewHandlerWith() `EXTRACTED`
- NewHandler() `EXTRACTED`
- BaseSubResourceHandler `EXTRACTED`
- NewCreateHandler() `EXTRACTED`
- UploadHandler `EXTRACTED`
- NewUploadHandler() `EXTRACTED`
- Handler `EXTRACTED`
- NewCompleteHandler() `EXTRACTED`
- NewHandler() `EXTRACTED`
- NewHandler() `EXTRACTED`
- ListHandler `EXTRACTED`
- AbortHandler `EXTRACTED`
- CompleteHandler `EXTRACTED`
- NewHandler() `EXTRACTED`
- CreateHandler `EXTRACTED`
- NewAbortHandler() `EXTRACTED`
- TaggingHandler `EXTRACTED`
- *…and 10 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*