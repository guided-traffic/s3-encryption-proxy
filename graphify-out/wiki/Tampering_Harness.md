# Tampering Harness

> 58 nodes · cohesion 0.07

## Key Concepts

- **context.Context** (465 connections)
- **leg** (12 connections) — `test/perf/client.go`
- **AESProvider** (9 connections) — `pkg/encryption/keyencryption/aes.go`
- **.GetBucketLocation()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.PutBucketLogging()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.PutObjectTagging()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **TamEnv** (7 connections) — `test/integration/360-degree-variants/segment_tamper_test.go`
- **.EncryptDEK()** (7 connections) — `pkg/encryption/interfaces.go`
- **smallObjectBatch()** (7 connections) — `test/perf/smallobject_test.go`
- **.DecryptDEK()** (6 connections) — `pkg/encryption/interfaces.go`
- **ReadStored()** (6 connections) — `test/e2e/harness/stored.go`
- **.GetBucketLocation()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketLogging()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectTagging()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketLoggingInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketLoggingOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectTaggingInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectTaggingOutput** (5 connections)
- **ExitProvider** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **.GetBucketLocation()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketLogging()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutObjectTagging()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketLocation()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- *... and 33 more nodes in this community*

## Relationships

- [Velero E2E Suite](Velero_E2E_Suite.md) (39 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (33 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (28 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (27 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (12 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (10 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (9 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (7 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (7 shared connections)
- [Harness: Backend](Harness-_Backend.md) (6 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (6 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/exit.go`
- `pkg/encryption/storedobject/storedobject_test.go`
- `test/e2e/harness/stored.go`
- `test/integration/360-degree-variants/segment_tamper_test.go`
- `test/perf/client.go`
- `test/perf/memory_test.go`
- `test/perf/smallobject_test.go`
- `test/perf/throughput_test.go`

## Audit Trail

- EXTRACTED: 586 (95%)
- INFERRED: 29 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*