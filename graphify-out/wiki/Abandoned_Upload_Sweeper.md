# Abandoned Upload Sweeper

> 10 nodes · cohesion 0.20

## Key Concepts

- **The Session Sweeper Measures Inactivity, Not Age** (7 connections) — `docs/developer/multipart.md`
- **Expiry Is Measured From the Last Part, Never From Creation** (2 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **optimizations.multipart_session_idle_timeout** (2 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **The Sweeper Aborts at the Backend Before It Forgets** (2 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **A Renamed Key Is Refused by Name, Not by a Generic Unknown-Key Error** (2 connections) — `docs/developer/configuration.md`
- **An Incomplete Multipart Upload Is Treated as a Leak** (1 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **AbortIncompleteMultipartUpload Lifecycle Rule** (1 connections) — `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- **CleanupExpiredSegmentedSessions** (1 connections) — `docs/developer/multipart.md`
- **Manager.SetMultipartAbandoner** (1 connections) — `docs/developer/multipart.md`
- **SegmentedSession.TouchWhileReading** (1 connections) — `docs/developer/multipart.md`

## Relationships

- [Strict Configuration Loading](Strict_Configuration_Loading.md) (1 shared connections)
- [Entity Tag Marker](Entity_Tag_Marker.md) (1 shared connections)

## Source Files

- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md`
- `docs/developer/configuration.md`
- `docs/developer/multipart.md`

## Audit Trail

- EXTRACTED: 10 (91%)
- INFERRED: 1 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*