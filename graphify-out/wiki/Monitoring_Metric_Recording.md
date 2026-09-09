# Monitoring Metric Recording

> 14 nodes · cohesion 0.15

## Key Concepts

- **middleware.go** (7 connections) — `internal/monitoring/middleware.go`
- **responseWriter** (7 connections) — `internal/monitoring/middleware.go`
- **TestMonRecordBytesTransferred()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonRecordEncryptionOperation()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonRecordS3Operation()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **RecordS3Operation()** (4 connections) — `internal/monitoring/middleware.go`
- **RecordEncryptionOperation()** (3 connections) — `internal/monitoring/middleware.go`
- **RecordBytesTransferred()** (2 connections) — `internal/monitoring/middleware.go`
- **.Flush()** (2 connections) — `internal/monitoring/middleware.go`
- **.FlushError()** (2 connections) — `internal/monitoring/middleware.go`
- **.Unwrap()** (2 connections) — `internal/monitoring/middleware.go`
- **RecordMultipartUpload()** (1 connections) — `internal/monitoring/middleware.go`
- **RecordMultipartUploadPart()** (1 connections) — `internal/monitoring/middleware.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/middleware.go`

## Relationships

- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (5 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (3 shared connections)
- [Prometheus Metrics](Prometheus_Metrics.md) (3 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`

## Audit Trail

- EXTRACTED: 23 (77%)
- INFERRED: 7 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*