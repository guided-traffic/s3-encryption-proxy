# SigV4 Authentication Rules

> 27 nodes · cohesion 0.08

## Key Concepts

- **ADR 0014 Authentication is SigV4, no rate limiting** (34 connections) — `README.md`
- **A control that exists only in configuration or documentation is worse than none** (7 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **An invalid configuration VALUE refuses the start and the error names the field (D8)** (5 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **5.0.0: an unknown configuration key stops the start** (4 connections) — `CHANGELOG.md`
- **Render-time refusals instead of crashloops (D5, D9, D10)** (4 connections) — `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`
- **ADR 0012 D15: The SigV4 payload hash is verified when s3_security.verify_payload_hash is on** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **A key that reads nothing is removed, not documented (D9, D12)** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **s3_security.max_clock_skew_seconds** (3 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Two authentication forms: header and pre-signed query** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **An authentication refusal answers the code that names what failed (D13)** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **A token without an exp claim is invalid (D3)** (2 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **No document, example or default ever prints a usable key (D8)** (2 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **SigV4 client authentication** (2 connections) — `README.md`
- **One clock-skew window governs both authentication forms** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **An http:// backend endpoint refuses the start** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **No multi-tenancy, no per-client keys or scopes** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **One broad backend credential, 52 interface methods all called** (2 connections) — `SECURITY_ARCHITECTURE.md`
- **s3_security.verify_payload_hash** (1 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Canonical query string sorts by parameter name, not by name=value** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Per-chunk aws-chunked signatures are not verified (D6)** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **The client address is a log field, never an identity (D8)** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **s3_security.max_presign_expiry_seconds** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Profiling endpoints on a loopback-only listener** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Replay inside the signature validity window is undefended** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **s3_clients static credentials (D2)** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- *... and 2 more nodes in this community*

## Relationships

- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (9 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (7 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (4 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (3 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (3 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (2 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (2 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (2 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (1 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (1 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (1 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md`

## Audit Trail

- EXTRACTED: 60 (94%)
- INFERRED: 4 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*