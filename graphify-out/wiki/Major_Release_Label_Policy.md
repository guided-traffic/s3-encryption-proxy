# Major Release Label Policy

> 11 nodes · cohesion 0.22

## Key Concepts

- **A Major Release Is Declared by the release:major Label** (6 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **The Integration and E2E Suites Are Part of the Product** (6 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **The CI Gate Is a Proxy-to-Direct Ratio, Never an Absolute Number** (4 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **A Control That Exists Only in Configuration Is Worse Than No Control** (3 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **The License Expiry Is Discovered by a Build, Not by an Environment** (3 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **The License Is a Fatal Startup Gate** (3 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **Published Key Material Is Rotated, Not Deleted** (3 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **Breaking Changes Collect on One Long-Lived Branch** (2 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **A Rewrite Is Preceded by the Complete Instrument Set** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **An End-to-End Suite Proves One Client, Never the Scope** (1 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Release Dry Run Compared Against the Label** (1 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`

## Relationships

- [SigV4 Without Rate Limiting](SigV4_Without_Rate_Limiting.md) (3 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (2 shared connections)
- [One Data Key Per Object](One_Data_Key_Per_Object.md) (2 shared connections)
- [Forward It Or Refuse It](Forward_It_Or_Refuse_It.md) (1 shared connections)
- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (1 shared connections)
- [ADR Authoring Rules](ADR_Authoring_Rules.md) (1 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`

## Audit Trail

- EXTRACTED: 20 (91%)
- INFERRED: 2 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*