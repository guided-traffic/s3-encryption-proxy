# SigV4 Without Rate Limiting

> 6 nodes · cohesion 0.40

## Key Concepts

- **A Configuration Key Exists Only If Code Reads It** (6 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **No Wall Clock on a Transfer** (5 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- **No Compatibility Is Owed for Data at Rest** (5 connections) — `docs/adr/0017-stored-data-compatibility-is-not-owed.md`
- **No Rate Limiting and No Per-Address Blocking** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Pre-Signed URL Expiry Cap and Uniform Clock Skew** (1 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **shutdown_timeout Is the Only Server-Side Transfer Budget** (1 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`

## Relationships

- [Major Release Label Policy](Major_Release_Label_Policy.md) (3 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (2 shared connections)
- [ADR Authoring Rules](ADR_Authoring_Rules.md) (1 shared connections)
- [One Data Key Per Object](One_Data_Key_Per_Object.md) (1 shared connections)
- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (1 shared connections)

## Source Files

- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0017-stored-data-compatibility-is-not-owed.md`

## Audit Trail

- EXTRACTED: 12 (86%)
- INFERRED: 2 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*