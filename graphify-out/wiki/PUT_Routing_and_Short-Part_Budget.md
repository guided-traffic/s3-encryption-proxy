# PUT Routing and Short-Part Budget

> 48 nodes · cohesion 0.05

## Key Concepts

- **ADR 0020 Performance is measured before and after** (35 connections) — `DEVELOPER.md`
- **ADR 0024 An upload forwards while it receives** (19 connections) — `DEVELOPER.md`
- **Performance** (12 connections) — `docs/developer/performance.md`
- **ADR 0011 D5: A part that cannot be a middle part is held under two bounds** (7 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **No switch, flag or configuration value disarms an assertion (D4)** (5 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **In-flight memory is bounded and configured (D4)** (4 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **/status: Dependency Health Reported, Never Acted On** (4 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **Five Subsystems With No Developer Page** (4 connections) — `docs/developer/README.md`
- **The internal multipart producer overlaps receive with send** (3 connections) — `DEVELOPER.md`
- **ADR 0012 D7: The verdict lands before anything is committed; on a failure nothing is stored** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **The memory bound is a test that fails, not a number in a report (D14)** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **optimizations.max_request_document_size (D8)** (3 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **Backend Round Trips Counted by Class Beside Answered Ones** (3 connections) — `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- **A PUT routes on PlaintextContentLength and nothing else** (2 connections) — `DEVELOPER.md`
- **A performance change carries a before and an after (D1, D4, D5)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Both candidate paths are measured and the loser is deleted (D2)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **No throughput measurement fails a build (D11)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **CI measures once, publishes, and moves on (D7, D22)** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **The unconsumed ranged-read body that killed connection pooling** (2 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **Receiving overlaps sending, and sealing never serialises the pipeline (D2, D3)** (2 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **The multipart deficit is per byte, not per request** (2 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **The restructuring ships with the format change, not after it (D6, D7)** (2 connections) — `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- **A Per-Request Log Line Is Debug** (2 connections) — `docs/developer/performance.md`
- **internal/monitoring/backend.go — the backend round-trip observer** (2 connections) — `docs/developer/README.md`
- **internal/monitoring/status.go — the /status document** (2 connections) — `docs/developer/README.md`
- *... and 23 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (11 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (5 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (5 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (3 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (3 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (2 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (2 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (2 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `DEVELOPER.md`
- `README.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0024-an-upload-forwards-while-it-receives.md`
- `docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md`
- `docs/developer/README.md`
- `docs/developer/performance.md`

## Audit Trail

- EXTRACTED: 89 (91%)
- INFERRED: 9 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*