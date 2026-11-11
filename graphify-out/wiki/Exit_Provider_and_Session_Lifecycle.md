# Exit Provider and Session Lifecycle

> 52 nodes · cohesion 0.05

## Key Concepts

- **Configuration: where a value comes from** (21 connections) — `docs/developer/configuration.md`
- **Package map** (14 connections) — `docs/developer/package-map.md`
- **pkg/s3enc client library** (9 connections) — `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- **Exit provider (type: exit)** (8 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Client-driven multipart upload** (8 connections) — `docs/developer/multipart.md`
- **Shutdown sweep aborts every held multipart upload** (6 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Sweeper aborts upload at backend before forgetting** (5 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **-0 entity tag marker** (5 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **optimizations.multipart_session_idle_timeout (inactivity expiry)** (4 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **Four-step shutdown order** (4 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **/readyz readiness endpoint (drain makes it false)** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Termination grace period = hold + shutdown budget + margin** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Strict ErrorUnused decode and keys refused by name** (4 connections) — `docs/developer/configuration.md`
- **Sweep bounded by what is left of shutdown_timeout** (3 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **/livez constant-success liveness endpoint** (3 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Module path github.com/guided-traffic/s3-encryption-proxy/v5** (3 connections) — `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- **${VAR} expansion in a named field list** (3 connections) — `docs/developer/configuration.md`
- **Permanent object state is 4xx, transient failure is 5xx** (3 connections) — `docs/developer/errors.md`
- **Mid-stream fault reporting by aborting the body** (3 connections) — `docs/developer/errors.md`
- **Session part table is the authority for Complete** (3 connections) — `docs/developer/multipart.md`
- **No fingerprint special-cased on the read path** (2 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **multipart_session_max_age refused by name** (2 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **shutdown_timeout configuration key** (2 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Shape-driven inverse of the -0 marker** (2 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **No probe depends on anything outside the process or on load** (2 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- *... and 27 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (12 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (5 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (5 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (3 shared connections)
- [Configuration Loading](Configuration_Loading.md) (3 shared connections)
- [Config: Config](Config-_Config.md) (3 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [Adr: 0039 The Analysis Tools Move With The Go Toolchain](Adr-_0039_The_Analysis_Tools_Move_With_The_Go_Toolchain.md) (1 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (1 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Error Mapping](Error_Mapping.md) (1 shared connections)

## Source Files

- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/0040-the-go-module-path-carries-the-major-version.md`
- `docs/adr/0041-the-project-ships-a-client-library-for-its-stored-format.md`
- `docs/developer/configuration.md`
- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/package-map.md`
- `internal/orchestration/segmented_session.go`

## Audit Trail

- EXTRACTED: 98 (94%)
- INFERRED: 6 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*