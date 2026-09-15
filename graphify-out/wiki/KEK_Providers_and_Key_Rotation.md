# KEK Providers and Key Rotation

> 76 nodes · cohesion 0.04

## Key Concepts

- **Managed Buckets: A Startup Readability Verdict And A Rewrap Pass** (41 connections) — `docs/tickets/040-managed-buckets.md`
- **ADR 0009 The metadata prefix is the proxy's namespace** (30 connections) — `DEVELOPER.md`
- **ADR 0004 One local key provider** (26 connections) — `README.md`
- **ADR 0002 One data key per object** (24 connections) — `DEVELOPER.md`
- **A Startup Verdict Per Managed Bucket** (9 connections) — `docs/tickets/040-managed-buckets.md`
- **A Pass That Moves A Bucket Onto The Current Key Encryption Key** (8 connections) — `docs/tickets/040-managed-buckets.md`
- **ADR 0004 D7: The wrap is AES-256-GCM with a fresh 16-byte salt per wrap, 76 bytes stored** (4 connections) — `docs/adr/0004-one-local-key-provider.md`
- **encryption.metadata_key_prefix** (4 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **Reconstruction Of A Session From The Backend Is Foreclosed** (4 connections) — `docs/tickets/036-high-availability.md`
- **A Backend Is Labelled By An Operator-Chosen Name, Never Its Endpoint** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **No Backend Probe At Startup And None Behind Readiness** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **Is The Bucket List An Inventory Or A Control** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **A Managed-Bucket List In The Configuration** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **The Per-Bucket Slope, Drawn On Purpose** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **A Readiness Switch While The Pass Runs** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **A Self-CopyObject Is A Full Server-Side Rewrite** (4 connections) — `docs/tickets/040-managed-buckets.md`
- **Exactly four s3ep-* metadata keys** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **AES-256-GCM Key Wrap (76 bytes)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0004 D1: There is exactly one local key-encryption provider, type aes** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0004 D12: The product exposes no key-rotation operation** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0004 D5: The refusal names the key, the generator and openssl rand -base64 32** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **encryption.providers[].config.aes_key** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Key Admission Rules (printable ASCII, 16 distinct bytes)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0008 D9: The proxy's metadata namespace never appears in a response** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0009 D2: The prefix is validated at startup against ^[a-z0-9][a-z0-9-]{2,}-$** (3 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- *... and 51 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (15 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (13 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (12 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (8 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (8 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (5 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (5 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (3 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (2 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (2 shared connections)
- [AES Example](AES_Example.md) (1 shared connections)

## Source Files

- `DEVELOPER.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `config/multi-example.yaml`
- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`
- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `docs/tickets/040-managed-buckets.md`

## Audit Trail

- EXTRACTED: 130 (68%)
- INFERRED: 60 (31%)
- AMBIGUOUS: 1 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*