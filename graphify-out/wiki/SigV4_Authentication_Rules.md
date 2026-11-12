# SigV4 Authentication Rules

> 90 nodes · cohesion 0.03

## Key Concepts

- **ADR 0013: A configuration key exists only if code reads it** (71 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0014: Authentication is SigV4, no rate limiting** (43 connections) — `README.md`
- **ADR 0037: The backend leg is trusted explicitly, and its failures are named** (15 connections) — `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- **Request authentication: what is checked before a handler runs** (14 connections) — `docs/security/request-authentication.md`
- **Upgrading from 3.x or 4.x to 5.x** (13 connections) — `docs/operations/upgrading.md`
- **H-2 Per-chunk signatures are never verified** (7 connections) — `docs/security/request-authentication.md`
- **Rule 2: a control that exists only in configuration or documentation is worse than none** (7 connections) — `docs/security/threat-model.md`
- **Ticket 039: Backend Certificate Verification Failure is Named** (7 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **D7 unworkable configuration refuses to start, never repaired** (6 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **What is not verified (payload, chunk signatures, replay)** (6 connections) — `docs/security/request-authentication.md`
- **A key exists only if code reads it and the read changes behaviour** (5 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Refusals: where the proxy says no rather than pretending** (5 connections) — `docs/security/refusals.md`
- **Unauthenticated probe exemption (/livez, /readyz)** (5 connections) — `docs/security/request-authentication.md`
- **Ticket 043: the backend is checked before the first client request** (5 connections) — `docs/tickets/043-the-backend-is-checked-before-the-first-client-request.md`
- **Complete configuration structure (every key the code reads)** (4 connections) — `CLAUDE.md`
- **Upgrading the chart to 5.0.0** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **No rate limiting and no per-address blocking** (4 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **A probe counts only when unsigned and query-free** (4 connections) — `docs/operations/monitoring.md`
- **Removed configuration keys now refuse the start** (4 connections) — `docs/operations/upgrading.md`
- **Clock-skew replay window (max_clock_skew_seconds)** (4 connections) — `docs/security/request-authentication.md`
- **SigV4 header and pre-signed forms** (4 connections) — `docs/security/request-authentication.md`
- **Proposed high_availability configuration block (question 37)** (4 connections) — `docs/tickets/036-high-availability.md`
- **Ticket 042: a certificate failure is not retried** (4 connections) — `docs/tickets/042-a-certificate-failure-is-not-retried.md`
- **config as one string rendered into the ConfigMap** (3 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Six dead s3_security keys and per-address failure accounting deleted** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- *... and 65 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (35 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (11 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (10 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (10 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (9 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (9 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (8 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (5 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (5 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (4 shared connections)
- [Key Material and Deployment Secrets](Key_Material_and_Deployment_Secrets.md) (4 shared connections)

## Source Files

- `CLAUDE.md`
- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/clients/velero.md`
- `docs/operations/configuration.md`
- `docs/operations/monitoring.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`
- `docs/security/refusals.md`
- `docs/security/request-authentication.md`
- `docs/security/stored-objects.md`
- `docs/security/threat-model.md`
- `docs/security/upload-integrity.md`
- `docs/tickets/036-high-availability.md`

## Audit Trail

- EXTRACTED: 228 (91%)
- INFERRED: 23 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*