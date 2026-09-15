# Any-S3-Client Scope and E2E Rules

> 58 nodes · cohesion 0.04

## Key Concepts

- **ADR 0025 Leaving is a supported mode** (37 connections) — `README.md`
- **ADR 0006 The proxy serves any S3 client** (30 connections) — `README.md`
- **Any-S3-Client Scope Rule** (5 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **ADR 0006 D1: The proxy serves any S3 client; no client defines the scope** (5 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **End-to-End Suite (evidence about one client)** (5 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **exit provider - leaving is a supported mode** (5 connections) — `README.md`
- **What the exit provider means for the threat model** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0013 D5: A plain-HTTP backend endpoint refuses the start under every provider** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **A removed configuration key is removed - no alias, no shim (D7)** (4 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **Under the Exit Provider There Is No Session at All** (4 connections) — `docs/developer/multipart.md`
- **The Exit Provider's Branch on Every Read and Write Path** (4 connections) — `docs/developer/request-paths.md`
- **aes KEK provider** (4 connections) — `README.md`
- **Checklist: adding an end-to-end client suite** (3 connections) — `DEVELOPER.md`
- **ADR 0006 D5: The end-to-end suite proves one client, never the scope** (3 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **ADR 0013 D4: s3_backend.use_tls is deleted; the transport is the scheme of the endpoint** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **s3_backends[].target_endpoint** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **The exit provider (D1)** (3 connections) — `docs/adr/0025-leaving-is-a-supported-mode.md`
- **Proven clients: Velero, rclone, s3cmd** (3 connections) — `README.md`
- **KEK rotation by fingerprint** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **5.0.0: the none and tink provider types are removed** (2 connections) — `CHANGELOG.md`
- **The e2e harness has two halves** (2 connections) — `CLAUDE.md`
- **One tool, one suite, one job - never bundled** (2 connections) — `CLAUDE.md`
- **The stored contract stays spelled out per suite** (2 connections) — `CLAUDE.md`
- **A ranged read plans without a key** (2 connections) — `DEVELOPER.md`
- **ADR 0006 D2: A compatibility question is answered against S3 semantics, not against one client** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- *... and 33 more nodes in this community*

## Relationships

- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (11 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (8 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (8 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (5 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (4 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (4 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (3 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (3 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (2 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `DEVELOPER.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0025-leaving-is-a-supported-mode.md`
- `docs/developer/multipart.md`
- `docs/developer/request-paths.md`

## Audit Trail

- EXTRACTED: 122 (95%)
- INFERRED: 6 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*