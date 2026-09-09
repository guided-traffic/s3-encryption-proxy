# Main Entrypoint Call Graph

> 24 nodes · cohesion 0.11

## Key Concepts

- **runProxy()** (19 connections) — `cmd/s3-encryption-proxy/main.go`
- **s3-encryption-proxy/main.go** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **initConfig()** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **main()** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **license.LicenseValidator.ValidateLicense** (4 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **SetLicenseInfo()** (4 connections) — `internal/monitoring/metrics.go`
- **runProxy$4 (monitoring server goroutine)** (3 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **runProxy$5 (proxy server goroutine)** (3 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **runProxy$6 (shutdown drain loop)** (3 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **proxy.Server.SetRequestTracker** (3 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **init()** (2 connections) — `cmd/s3-encryption-proxy/main.go`
- **Main Entrypoint Call Graph (gocallvis SVG, focus cmd/s3-encryption-proxy)** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **cobra.Command.Execute** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **Graceful shutdown drain with atomic request counter** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **License startup gate** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **Listener failure asymmetry (fatal proxy, non-fatal monitoring)** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **monitoring.Server.Start** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **proxy.Server.Start** (2 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **os.Exit** (1 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **os/signal.Notify** (1 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **Startup sequence: config, license, metrics, then listeners** (1 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **github.com/spf13/cobra.Command** (1 connections)
- **license.LicenseValidator.Stop** (1 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **proxy.Server.SetShutdownStateHandler** (1 connections) — `docs/architecture/callgraph_main_entrypoint.svg`

## Relationships

- [Configuration Accessors](Configuration_Accessors.md) (3 shared connections)
- [Prometheus Metrics](Prometheus_Metrics.md) (3 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (2 shared connections)
- [Config File Loading](Config_File_Loading.md) (1 shared connections)
- [pprof Profiling Server](pprof_Profiling_Server.md) (1 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `docs/architecture/callgraph_main_entrypoint.svg`
- `internal/monitoring/metrics.go`

## Audit Trail

- EXTRACTED: 26 (62%)
- INFERRED: 16 (38%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*