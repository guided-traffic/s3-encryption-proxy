# Monitoring Server

> 24 nodes · cohesion 0.16

## Key Concepts

- **monitoring/server_coverage_test.go** (13 connections) — `internal/monitoring/server_coverage_test.go`
- **NewServer()** (13 connections) — `internal/monitoring/server.go`
- **Monserve()** (9 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerMetricsEndpoint()** (6 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfreeAddr()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerInfoEndpoint()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartServesAndShutsDownOnContextCancel()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingListener** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **MonfailingWriter** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **.Header()** (5 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerEndpointsSurviveWriteFailures()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerHealthEndpoint()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerNeverServesPprof()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartLogsListenFailure()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **.Close()** (4 connections) — `internal/monitoring/server_coverage_test.go`
- **monitoring/server.go** (3 connections) — `internal/monitoring/server.go`
- **TestMonNewServerConfiguration()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **TestMonServerStartReportsShutdownFailure()** (3 connections) — `internal/monitoring/server_coverage_test.go`
- **Config** (2 connections) — `internal/monitoring/server.go`
- **.Accept()** (2 connections) — `internal/monitoring/server_coverage_test.go`
- **net.Listener** (1 connections)
- **Server** (1 connections)
- **.Write()** (1 connections) — `internal/monitoring/server_coverage_test.go`
- **.WriteHeader()** (1 connections) — `internal/monitoring/server_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (11 shared connections)
- [pprof Listener](pprof_Listener.md) (4 shared connections)
- [Metrics and Main Entry](Metrics_and_Main_Entry.md) (2 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (2 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (1 shared connections)
- [License Types](License_Types.md) (1 shared connections)
- [Response Writer Hijacking](Response_Writer_Hijacking.md) (1 shared connections)

## Source Files

- `internal/monitoring/server.go`
- `internal/monitoring/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 53 (82%)
- INFERRED: 12 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*