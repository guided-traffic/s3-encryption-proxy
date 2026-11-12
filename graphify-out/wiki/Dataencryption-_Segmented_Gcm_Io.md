# Dataencryption: Segmented Gcm Io

> 18 nodes · cohesion 0.12

## Key Concepts

- **runProxy()** (11 connections) — `cmd/s3-encryption-proxy/main.go`
- **NewPprofServer()** (7 connections) — `internal/monitoring/pprof.go`
- **startupWarnings()** (6 connections) — `cmd/s3-encryption-proxy/main.go`
- **PprofServer** (5 connections) — `internal/monitoring/pprof.go`
- **Server** (5 connections) — `internal/monitoring/server.go`
- **TestPprofServerServesOnlyProfiling()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerStartServesAndShutsDownOnContextCancel()** (4 connections) — `internal/monitoring/pprof_coverage_test.go`
- **monitoringPlan()** (3 connections) — `cmd/s3-encryption-proxy/main.go`
- **TestMainMonitoringPlanKeepsPprofIndependent()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainStartupWarnings()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **net/http.Server** (3 connections)
- **TestPprofNewServerConfiguration()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **TestPprofServerReportsItsFailures()** (3 connections) — `internal/monitoring/pprof_coverage_test.go`
- **.Start()** (3 connections) — `internal/monitoring/server.go`
- **startupWarning** (3 connections) — `cmd/s3-encryption-proxy/main.go`
- **github.com/spf13/cobra.Command** (2 connections)
- **.Start()** (2 connections) — `internal/monitoring/pprof.go`
- **github.com/sirupsen/logrus.Fields** (1 connections)

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (14 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (7 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (5 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [Misc (15)](Misc_15.md) (2 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Misc (41)](Misc_41.md) (1 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`
- `internal/monitoring/pprof.go`
- `internal/monitoring/pprof_coverage_test.go`
- `internal/monitoring/server.go`

## Audit Trail

- EXTRACTED: 43 (81%)
- INFERRED: 10 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*