# Monitoring Middleware Tests

> 27 nodes · cohesion 0.13

## Key Concepts

- **middleware_coverage_test.go** (15 connections) — `internal/monitoring/middleware_coverage_test.go`
- **net.Conn** (8 connections)
- **MonrequestMetric()** (7 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonFlushErrorWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **MonHijackWriter** (6 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareRecordsRoutedRequest()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareTracksActiveConnections()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonHTTPMiddlewareUnknownEndpoint()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterForwardsToTheLiveWriter()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Hijack()** (5 connections) — `internal/proxy/middleware/http_middleware_coverage_test.go`
- **.Hijack()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Write()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.WriteHeader()** (5 connections) — `internal/monitoring/middleware_coverage_test.go`
- **bufio.ReadWriter** (4 connections)
- **TestMonHTTPMiddlewareDefaultsToStatus200()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterCapturesStatusCode()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **TestMonResponseWriterKeepsTheWriterCapabilities()** (4 connections) — `internal/monitoring/middleware_coverage_test.go`
- **HTTPMiddleware()** (4 connections) — `internal/monitoring/middleware.go`
- **TestMonRecordMultipartMetrics()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Hijack()** (3 connections) — `internal/proxy/middleware/logging.go`
- **.FlushError()** (3 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Hijack()** (3 connections) — `internal/monitoring/middleware.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Header()** (2 connections) — `internal/monitoring/middleware_coverage_test.go`
- **.Flush()** (1 connections) — `internal/monitoring/middleware_coverage_test.go`
- *... and 2 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (9 shared connections)
- [Monitoring Metric Recording](Monitoring_Metric_Recording.md) (5 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (4 shared connections)
- [Prometheus Metrics](Prometheus_Metrics.md) (4 shared connections)
- [Logging Response Writer](Logging_Response_Writer.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Failing Listener Test Fake](Failing_Listener_Test_Fake.md) (1 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (1 shared connections)

## Source Files

- `internal/monitoring/middleware.go`
- `internal/monitoring/middleware_coverage_test.go`
- `internal/proxy/middleware/http_middleware_coverage_test.go`
- `internal/proxy/middleware/logging.go`

## Audit Trail

- EXTRACTED: 70 (93%)
- INFERRED: 5 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*