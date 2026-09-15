# Multipart Semantics and ETag Marker

> 68 nodes · cohesion 0.03

## Key Concepts

- **Request Paths** (21 connections) — `docs/developer/request-paths.md`
- **Multipart Uploads** (15 connections) — `docs/developer/multipart.md`
- **What One In-Flight Request Costs in Memory** (10 connections) — `docs/developer/performance.md`
- **Three Entity-Tag Gates and Two Places That Must Never See the Marker** (7 connections) — `docs/developer/request-paths.md`
- **The PUT Path and Its Routing Decision** (7 connections) — `docs/developer/request-paths.md`
- **The Client's Checksum Is Verified Against the Decoded Plaintext and Dropped** (6 connections) — `docs/developer/request-paths.md`
- **fetchObjectTail** (6 connections) — `docs/developer/request-paths.md`
- **The -0 Entity Tag Marker** (4 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **The Internal Multipart Producer** (4 connections) — `docs/developer/multipart.md`
- **The Process-Wide Short-Part Budget** (4 connections) — `docs/developer/multipart.md`
- **internal/orchestration — The Encryption Facade the Handlers Call** (4 connections) — `docs/developer/package-map.md`
- **Listings Report the Plaintext Size Without a Per-Key Round Trip** (4 connections) — `docs/developer/request-paths.md`
- **uploadStreamedPart** (4 connections) — `docs/developer/multipart.md`
- **Verdict()** (4 connections) — `internal/proxy/request/checksum.go`
- **A Test States the Target Behaviour** (3 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **The Marker Is Invertible and the Inverse Is Driven by Shape** (3 connections) — `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- **A Permanent State Is a 4xx, a Transient Failure a 5xx** (3 connections) — `docs/developer/errors.md`
- **The Client-Driven Multipart Upload** (3 connections) — `docs/developer/multipart.md`
- **The Part Table Is the Authority, Not the Client's Completion Document** (3 connections) — `docs/developer/multipart.md`
- **A Part Is Streamed or Held, and the Declared Length Decides** (3 connections) — `docs/developer/multipart.md`
- **A Client That Hangs Up Mid-Body Must Not Commit** (3 connections) — `docs/developer/multipart.md`
- **Four Handler Files Reach Past the Orchestration Facade** (3 connections) — `docs/developer/package-map.md`
- **HEAD Is One Ranged Read of the Object's Last 40 Bytes** (3 connections) — `docs/developer/request-paths.md`
- **The Response Is Composed From an Allowlist, Never Proxied** (3 connections) — `docs/developer/request-paths.md`
- **A Short Body Cannot Become a Stored Object on Either Write Path** (3 connections) — `docs/developer/request-paths.md`
- *... and 43 more nodes in this community*

## Relationships

- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (6 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (6 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [Segmented GCM](Segmented_GCM.md) (3 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (2 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (2 shared connections)
- [Shutdown Order and Probes](Shutdown_Order_and_Probes.md) (2 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (2 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (2 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (2 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)

## Source Files

- `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/package-map.md`
- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `internal/proxy/request/checksum.go`

## Audit Trail

- EXTRACTED: 118 (97%)
- INFERRED: 4 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*