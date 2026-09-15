# Contributor Guide and KMS Provider ADR

> 86 nodes · cohesion 0.03

## Key Concepts

- **ADR 0013 A configuration key exists only if code reads it** (60 connections) — `README.md`
- **ADR 0018 A major release is declared by a label** (30 connections) — `CONTRIBUTING.md`
- **ADR 0005 A KMS key is a provider (decided, unbuilt)** (29 connections) — `README.md`
- **ADR 0016 The license is a startup gate** (22 connections) — `README.md`
- **ADR 0021 Key material is generated, never committed** (22 connections) — `CONTRIBUTING.md`
- **DEVELOPER.md contributor entry point** (10 connections) — `DEVELOPER.md`
- **README.md front page** (9 connections) — `README.md`
- **CONTRIBUTING.md** (8 connections) — `CONTRIBUTING.md`
- **CLAUDE.md AI coding instructions** (6 connections) — `CLAUDE.md`
- **KMS-Backed KEK Provider (decided, unbuilt)** (6 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **The complete configuration key reference** (5 connections) — `README.md`
- **SECURITY_ARCHITECTURE.md** (5 connections) — `SECURITY_ARCHITECTURE.md`
- **The complete configuration structure** (4 connections) — `CLAUDE.md`
- **ADR 0013 D2: The six dead s3_security keys are deleted with the failure accounting behind them** (4 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **The S3 backend is hostile** (4 connections) — `SECURITY_ARCHITECTURE.md`
- **The semantic-release dry run is a separate workflow** (3 connections) — `DEVELOPER.md`
- **ADR 0005 D12: The KMS provider is a key-encryption-key provider only; the object format is unaffected** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0005 D13: It ships after the storage format rewrite, in its own additive release** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0005 D5: A provider that names a remote key it cannot reach does not exist (startup error)** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0005 D7: Every KMS call carries an explicit configured timeout** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **HashiCorp Vault Transit** (3 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **ADR 0013 D11: An unknown configuration key refuses the start, and the refusal names the key** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0013 D13: A configured license_file is binding; a path that does not resolve refuses the start** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0013 D14: A command-line flag does not override a configuration key** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0013 D6: max_presign_expiry_seconds exists and lands with the code that enforces it** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- *... and 61 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (15 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (14 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (12 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (12 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (12 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (11 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (9 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (7 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (5 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (5 shared connections)
- [Golangci](Golangci.md) (4 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (4 shared connections)

## Source Files

- `CLAUDE.md`
- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/tickets/037-multiple-backends.md`

## Audit Trail

- EXTRACTED: 222 (96%)
- INFERRED: 9 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*