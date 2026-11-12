# Key Material and Deployment Secrets

> 35 nodes · cohesion 0.07

## Key Concepts

- **Operations: Configuration guide** (15 connections) — `docs/operations/configuration.md`
- **Operations: Monitoring** (13 connections) — `docs/operations/monitoring.md`
- **Operations: Deployment** (11 connections) — `docs/operations/deployment.md`
- **Operations: Upgrading** (9 connections) — `docs/operations/upgrading.md`
- **Eleven s3ep_* Prometheus series** (7 connections) — `docs/operations/monitoring.md`
- **Where a failed proof surfaces (before vs after the response)** (6 connections) — `docs/security/stored-objects.md`
- **One instance per release; the chart refuses a second** (5 connections) — `docs/operations/deployment.md`
- **Helm chart install** (4 connections) — `docs/operations/deployment.md`
- **Three installation paths** (4 connections) — `docs/operations/deployment.md`
- **config/default.yaml (the image's own configuration)** (3 connections) — `docs/operations/configuration.md`
- **${VAR} environment reference mechanism** (3 connections) — `docs/operations/configuration.md`
- **Shipped configuration examples** (3 connections) — `docs/operations/configuration.md`
- **Docker run with the image's own configuration** (3 connections) — `docs/operations/deployment.md`
- **The KEK belongs in a Secret, never in the ConfigMap** (3 connections) — `docs/operations/deployment.md`
- **PrometheusRule alerting rules ship with the chart** (3 connections) — `docs/operations/monitoring.md`
- **GET /status document** (3 connections) — `docs/operations/monitoring.md`
- **Within 5.x: the release that stops checking a licence** (3 connections) — `docs/operations/upgrading.md`
- **Docker Compose deployment** (2 connections) — `docs/operations/deployment.md`
- **403 InvalidObjectState refusals for foreign objects and bad key material** (2 connections) — `docs/operations/integrity.md`
- **Passive backend observation (no synthetic check)** (2 connections) — `docs/operations/monitoring.md`
- **Unauthenticated metrics listener** (2 connections) — `docs/operations/monitoring.md`
- **One Prometheus registry** (2 connections) — `docs/operations/monitoring.md`
- **s3ep_backend_responses_total** (2 connections) — `docs/operations/monitoring.md`
- **s3ep_backend_transport_failures_total** (2 connections) — `docs/operations/monitoring.md`
- **s3ep_encryption_provider_info** (2 connections) — `docs/operations/monitoring.md`
- *... and 10 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (13 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (4 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (4 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (4 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (3 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (2 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)

## Source Files

- `docs/operations/configuration.md`
- `docs/operations/deployment.md`
- `docs/operations/integrity.md`
- `docs/operations/monitoring.md`
- `docs/operations/upgrading.md`
- `docs/security/stored-objects.md`

## Audit Trail

- EXTRACTED: 75 (93%)
- INFERRED: 6 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*