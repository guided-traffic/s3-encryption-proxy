# Misc (15)

> 51 nodes · cohesion 0.09

## Key Concepts

- **context.Context** (465 connections)
- **measureThroughput()** (13 connections) — `test/perf/throughput_test.go`
- **leg** (12 connections) — `test/perf/client.go`
- **ensureBucket()** (10 connections) — `test/perf/client.go`
- **TestUploadPathComparison()** (10 connections) — `test/perf/uploadpath_test.go`
- **emptyBucket()** (9 connections) — `test/perf/client.go`
- **.DeleteObjectTagging()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.GetBucketCors()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.GetBucketLifecycleConfiguration()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.GetBucketTagging()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **TamEnv** (7 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **smallObjectBatch()** (7 connections) — `test/perf/smallobject_test.go`
- **ReadStored()** (6 connections) — `test/e2e/harness/stored.go`
- **median()** (6 connections) — `test/perf/unwrap_test.go`
- **.DeleteObjectTagging()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketCors()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLifecycleConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketTagging()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketCorsInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketCorsOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketTaggingInput** (5 connections)
- *... and 26 more nodes in this community*

## Relationships

- [Velero E2E Suite](Velero_E2E_Suite.md) (35 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (32 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (31 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (28 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (17 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (16 shared connections)
- [Misc (12)](Misc_12.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (10 shared connections)
- [Tampering Harness](Tampering_Harness.md) (10 shared connections)
- [Harness: Backend](Harness-_Backend.md) (8 shared connections)
- [Shutdown: Shutdown Test](Shutdown-_Shutdown_Test.md) (7 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (7 shared connections)

## Source Files

- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`
- `test/e2e/harness/stored.go`
- `test/integration/360-degree-variants/segment_tamper_test.go`
- `test/perf/client.go`
- `test/perf/memory_test.go`
- `test/perf/smallobject_test.go`
- `test/perf/throughput_test.go`
- `test/perf/unwrap_test.go`
- `test/perf/uploadpath_test.go`

## Audit Trail

- EXTRACTED: 585 (93%)
- INFERRED: 42 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*