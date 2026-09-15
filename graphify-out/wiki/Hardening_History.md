# Hardening History

> 19 nodes · cohesion 0.15

## Key Concepts

- **403 InvalidObjectState for objects this proxy did not write** (9 connections) — `docs/operations/integrity.md`
- **Hardening history — the eight closed items** (8 connections) — `docs/security/hardening-history.md`
- **Under exit the decision is taken per object** (5 connections) — `docs/operations/integrity.md`
- **Ranged reads (Range: bytes=...)** (5 connections) — `docs/operations/s3-api.md`
- **H-1 Ranged reads are not verified by the proxy** (4 connections) — `docs/security/hardening-history.md`
- **s3ep_object_integrity_failures_total** (3 connections) — `docs/operations/monitoring.md`
- **Objects written by an earlier release cannot be read** (3 connections) — `docs/operations/upgrading.md`
- **H-10 Three configuration decisions specified and not built** (3 connections) — `docs/security/hardening-history.md`
- **H-11 The pass-through provider was not a pass-through above one part** (3 connections) — `docs/security/hardening-history.md`
- **H-5 A tampered object is delivered, not refused** (3 connections) — `docs/security/hardening-history.md`
- **H-6 An object without encryption metadata is served as plaintext** (3 connections) — `docs/security/hardening-history.md`
- **H-9 The replaced format's decrypt path is still in the tree** (3 connections) — `docs/security/hardening-history.md`
- **kopia reads pack blobs with ranges** (2 connections) — `docs/operations/clients/velero.md`
- **A fault found mid-stream cuts the body** (2 connections) — `docs/operations/integrity.md`
- **Pre-signed URLs and max_presign_expiry_seconds** (2 connections) — `docs/operations/s3-api.md`
- **max_clock_skew_seconds now governs both auth forms** (2 connections) — `docs/operations/upgrading.md`
- **type: "none" is gone; the provider is now exit** (2 connections) — `docs/operations/upgrading.md`
- **The refusals are 4xx deliberately** (1 connections) — `docs/operations/integrity.md`
- **Manager.DecryptDataWithMetadata (deleted)** (1 connections) — `docs/security/hardening-history.md`

## Relationships

- [Integrity](Integrity.md) (3 shared connections)
- [Configuration](Configuration.md) (3 shared connections)
- [Segment Tamper](Segment_Tamper.md) (3 shared connections)
- [Monitoring](Monitoring.md) (2 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (1 shared connections)
- [027 Whole Object Read](027_Whole_Object_Read.md) (1 shared connections)
- [Conformance Run](Conformance_Run.md) (1 shared connections)

## Source Files

- `docs/operations/clients/velero.md`
- `docs/operations/integrity.md`
- `docs/operations/monitoring.md`
- `docs/operations/s3-api.md`
- `docs/operations/upgrading.md`
- `docs/security/hardening-history.md`

## Audit Trail

- EXTRACTED: 35 (90%)
- INFERRED: 4 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*