# One Local Key Provider

> 6 nodes · cohesion 0.33

## Key Concepts

- **Provider Selection by s3ep-kek-fingerprint** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Key Admission Rules (No Passphrases)** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Authenticated AES-256-GCM Key Wrap with Per-Wrap Salt** (2 connections) — `docs/adr/0004-one-local-key-provider.md`
- **Custody by Injection Is Not a KMS** (2 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **No Working Key Material or License Token in the Repository** (2 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **The KMS Fingerprint Identifies the Key, Not Its Material** (1 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`

## Relationships

- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (2 shared connections)
- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (1 shared connections)

## Source Files

- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`

## Audit Trail

- EXTRACTED: 6 (75%)
- INFERRED: 2 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*