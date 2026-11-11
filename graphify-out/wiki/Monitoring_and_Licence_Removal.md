# Monitoring and Licence Removal

> 74 nodes · cohesion 0.04

## Key Concepts

- **Helm chart README** (31 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **ADR 0034: A probe reports the process, never its dependencies** (31 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **ADR 0016: Apache 2.0, no license check** (23 connections) — `docs/adr/0016-the-proxy-is-apache-licensed-and-checks-no-license.md`
- **ADR 0030: The network boundary belongs to the administrator** (18 connections) — `docs/tickets/037-multiple-backends.md`
- **Operations: Monitoring** (15 connections) — `docs/operations/monitoring.md`
- **ADR 0037: The backend leg is trusted explicitly, and its failures are named** (14 connections) — `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- **ADR 0026: The proxy terminates TLS at its own Service** (13 connections) — `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- **ADR 0033: A proxy instance holds its uploads** (13 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **Unauthenticated monitoring listener discloses the active provider** (8 connections) — `docs/security/request-authentication.md`
- **Eleven s3ep_* Prometheus series** (7 connections) — `docs/operations/monitoring.md`
- **Where a failed proof surfaces (before vs after the response)** (6 connections) — `docs/security/stored-objects.md`
- **/livez and /readyz probe endpoints** (5 connections) — `docs/operations/monitoring.md`
- **Unauthenticated probe exemption (/livez, /readyz)** (5 connections) — `docs/security/request-authentication.md`
- **Ticket 043: the backend is checked before the first client request** (5 connections) — `docs/tickets/043-the-backend-is-checked-before-the-first-client-request.md`
- **One instance; chart refuses replicaCount>1 and autoscaling** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Upgrading the chart to 5.0.0** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **D13 license_file accepted and ignored** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Nothing in the product checks a license** (4 connections) — `docs/adr/0016-the-proxy-is-apache-licensed-and-checks-no-license.md`
- **serviceTLS chart values block** (4 connections) — `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- **/status document on the monitoring listener** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **A probe counts only when unsigned and query-free** (4 connections) — `docs/operations/monitoring.md`
- **Ticket 042: a certificate failure is not retried** (4 connections) — `docs/tickets/042-a-certificate-failure-is-not-retried.md`
- **Release 5.2.0: Apache 2.0, license check removed** (3 connections) — `CHANGELOG.md`
- **Upgrading to the release that stops checking a licence** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Liveness /livez constant 200, readiness /readyz 503 on drain** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- *... and 49 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (26 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (19 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (15 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (13 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (9 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (8 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (5 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (5 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (4 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0016-the-proxy-is-apache-licensed-and-checks-no-license.md`
- `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/request-paths.md`
- `docs/operations/monitoring.md`
- `docs/security/request-authentication.md`
- `docs/security/stored-objects.md`
- `docs/security/threat-model.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/042-a-certificate-failure-is-not-retried.md`
- `docs/tickets/043-the-backend-is-checked-before-the-first-client-request.md`

## Audit Trail

- EXTRACTED: 203 (92%)
- INFERRED: 17 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*