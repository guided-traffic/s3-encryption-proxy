# Storage Format Invariants

> 10 nodes · cohesion 0.20

## Key Concepts

- **The Storage Format (s3ep-gcm-seg-v2)** (8 connections) — `docs/developer/storage-format.md`
- **The Four Metadata Keys That Mark an Object as Ours** (4 connections) — `docs/developer/storage-format.md`
- **The Ranged-Read Window and Its Amplification Bound** (3 connections) — `docs/developer/storage-format.md`
- **Invariant 1: Each Seal Is Bound to Its Position and Its Object** (2 connections) — `docs/developer/storage-format.md`
- **Foreign Object Versus Missing Key Material** (1 connections) — `docs/developer/storage-format.md`
- **Mutation Round Before a Crypto Change Is Called Done** (1 connections) — `docs/developer/storage-format.md`
- **Invariant 3: A Nonce Is Never Reused Under One Key** (1 connections) — `docs/developer/storage-format.md`
- **Server-Side Copy Is Refused Because the AAD Binds the Object Key** (1 connections) — `docs/developer/storage-format.md`
- **Manager.ClaimsSegmentedFormat** (1 connections) — `docs/developer/storage-format.md`
- **Manager.IsSegmentedObject** (1 connections) — `docs/developer/storage-format.md`

## Relationships

- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (1 shared connections)
- [Entity Tag Marker](Entity_Tag_Marker.md) (1 shared connections)
- [Integrity Failure Reporting](Integrity_Failure_Reporting.md) (1 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)

## Source Files

- `docs/developer/storage-format.md`

## Audit Trail

- EXTRACTED: 14 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*