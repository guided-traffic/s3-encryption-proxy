# Proxy-Owned Part Layout

> 85 nodes · cohesion 0.04

## Key Concepts

- **ADR 0011 The proxy owns the part layout** (48 connections) — `DEVELOPER.md`
- **High Availability Across Proxy Instances** (47 connections) — `docs/tickets/036-high-availability.md`
- **ADR 0034: A probe reports the process, never its dependencies** (24 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **ADR 0015: A Transfer Is Bounded by the Client and by Shutdown** (23 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0029: The shutdown budget finishes work and sweeps what cannot be finished** (20 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **ADR 0033 A proxy instance holds its uploads** (15 connections) — `README.md`
- **Shared Session Table In Valkey With Sentinel** (15 connections) — `docs/tickets/036-high-availability.md`
- **ADR 0028: An Abandoned Upload Is Ended, Not Forgotten** (14 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Architecture Decision Records Index** (12 connections) — `docs/adr/README.md`
- **Package Map** (12 connections) — `docs/developer/package-map.md`
- **The Ticket Index** (9 connections) — `docs/tickets/README.md`
- **ADR 0013 D7: A configuration that cannot work, or silently disables a protection, refuses to start** (6 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0011 D2: A client-driven upload must use uniform, segment-aligned parts, checked at Complete** (5 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **ADR 0011 D6: Complete is built from the proxy's own part table, never from the client's ETags** (5 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **The Proxy's Own Part Table** (5 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **The Held Short Part Never Leaves The Holder's Memory** (5 connections) — `docs/tickets/036-high-availability.md`
- **Unauthenticated probe paths /livez and /readyz (D11, D14)** (4 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **pkg/encryption — Crypto Primitives, No Business Logic** (4 connections) — `docs/developer/package-map.md`
- **Multipart Across Backends: One Upload Id Per Backend** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **ADR 0011 D4: The trailer is an extra part, or rides a held last part; 9999 usable part numbers** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **No rate limiting and no per-address blocking (D7)** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **The preStop Hold Has No Opt-Out** (3 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Coordination Is A Write Per Part, Not A Fetch Per Upload** (3 connections) — `docs/tickets/036-high-availability.md`
- **No Probe Ever Depends On The Coordination Store** (3 connections) — `docs/tickets/036-high-availability.md`
- **The Idle Clock Is Process-Local And Cannot Be A Lease Value** (3 connections) — `docs/tickets/036-high-availability.md`
- *... and 60 more nodes in this community*

## Relationships

- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (17 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (15 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (15 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (12 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (11 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (9 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (8 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (8 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (8 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (7 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (6 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (6 shared connections)

## Source Files

- `DEVELOPER.md`
- `README.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md`
- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/adr/README.md`
- `docs/developer/configuration.md`
- `docs/developer/package-map.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 203 (75%)
- INFERRED: 66 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*