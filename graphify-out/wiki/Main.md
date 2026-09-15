# Main

> 19 nodes · cohesion 0.16

## Key Concepts

- **runProxy()** (11 connections) — `cmd/s3-encryption-proxy/main.go`
- **s3-encryption-proxy/main.go** (9 connections) — `cmd/s3-encryption-proxy/main.go`
- **runShutdownTail()** (8 connections) — `cmd/s3-encryption-proxy/main.go`
- **s3-encryption-proxy/shutdown_test.go** (7 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **startupWarnings()** (5 connections) — `cmd/s3-encryption-proxy/main.go`
- **monitoringPlan()** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **TestMainMonitoringPlanKeepsPprofIndependent()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainShutdownClosesTheListenerEvenWhenTheSweepFails()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainShutdownExhaustedBudgetStillSweepsAndCloses()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainShutdownListenerGetsTheSameDeadlineAsTheSweep()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainShutdownSweepGetsWhatIsLeftOfTheBudget()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainShutdownSweepsBeforeClosingTheListener()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **TestMainStartupWarnings()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **startupWarning** (3 connections) — `cmd/s3-encryption-proxy/main.go`
- **initConfig()** (2 connections) — `cmd/s3-encryption-proxy/main.go`
- **main()** (2 connections) — `cmd/s3-encryption-proxy/main.go`
- **init()** (1 connections) — `cmd/s3-encryption-proxy/main.go`
- **github.com/sirupsen/logrus.Fields** (1 connections)
- **github.com/spf13/cobra.Command** (1 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (3 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (2 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (1 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [Pprof](Pprof.md) (1 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`

## Audit Trail

- EXTRACTED: 40 (85%)
- INFERRED: 7 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*