# Monitoring and Licence Removal

> 106 nodes · cohesion 0.03

## Key Concepts

- **Architecture Decision Records index (docs/adr/README.md)** (45 connections) — `docs/adr/README.md`
- **ADR 0034: A probe reports the process, never its dependencies** (36 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Helm chart README** (30 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Ticket 036: High availability (several instances, multipart included)** (28 connections) — `docs/tickets/036-high-availability.md`
- **ADR 0015: A transfer is bounded by the client and by shutdown, not by a server wall clock** (26 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **ADR 0029: The shutdown budget finishes work, and sweeps what cannot be finished** (25 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **ADR 0016: Apache 2.0, no license check** (24 connections) — `docs/adr/0016-the-proxy-is-apache-licensed-and-checks-no-license.md`
- **ADR 0028: An abandoned upload is ended, not forgotten** (24 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **ADR 0030: The network boundary belongs to the administrator** (21 connections) — `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- **ADR 0026: The proxy terminates TLS at its own Service** (19 connections) — `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- **ADR 0033: A proxy instance holds its uploads** (14 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **Ticket 038: s3-encryption-operator** (11 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Multipart session sweep and shutdown abort** (8 connections) — `docs/security/key-management.md`
- **Unauthenticated monitoring listener discloses the active provider** (8 connections) — `docs/security/request-authentication.md`
- **Every held multipart upload is aborted at shutdown (D2)** (7 connections) — `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- **Graceful shutdown ends open uploads** (6 connections) — `docs/operations/configuration.md`
- **/livez liveness is a constant success (D2)** (5 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **/livez and /readyz probe endpoints** (5 connections) — `docs/operations/monitoring.md`
- **Decision 9: pin is a peer address plus random instance identity** (5 connections) — `docs/tickets/036-high-availability.md`
- **terminationGracePeriodSeconds = preStopSleepSeconds + shutdown_timeout + 5** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Sweeper aborts the upload at the backend before forgetting (D2)** (4 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **/readyz readiness is a lifecycle signal the drain makes false (D3/D4)** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **S3 route middleware chain (drain guard first, SigV4 second)** (4 connections) — `docs/developer/request-paths.md`
- **Integration suites under test/integration** (4 connections) — `docs/developer/testing.md`
- **shutdown integration package** (4 connections) — `docs/developer/testing.md`
- *... and 81 more nodes in this community*

## Relationships

- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (35 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (17 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (15 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (15 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (15 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (13 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (12 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (9 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (8 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (7 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (5 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (3 shared connections)

## Source Files

- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0016-the-proxy-is-apache-licensed-and-checks-no-license.md`
- `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/README.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/configuration.md`
- `docs/operations/monitoring.md`
- `docs/security/key-management.md`
- `docs/security/request-authentication.md`
- `docs/tickets/036-high-availability.md`

## Audit Trail

- EXTRACTED: 333 (96%)
- INFERRED: 13 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*