# Response Composition Rules

> 64 nodes · cohesion 0.04

## Key Concepts

- **ADR 0008 Every response describes the proxy** (39 connections) — `DEVELOPER.md`
- **ADR 0010: Sizes and Listings Describe the Plaintext** (31 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0032: The Entity Tag Is a Change Token, Never a Content Digest** (17 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **A Backend Certificate The Proxy Does Not Trust Is Named** (13 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **Plaintext Size by Arithmetic on the Stored Size** (5 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0008 D13: Whether a backend header may be restated is decided by what the header describes** (4 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **The CA Bundle And A Backend Under A Private CA** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **One Error-Level Line With Its Own Message And An x509 reason** (4 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **ADR 0008 D1: Every response is composed by the proxy; a backend response object is never serialised as received** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D4: The <Location> names the proxy as the client addressed it** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0010 D1: Every size the proxy reports describes the plaintext the client would receive** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0010 D12: <ETag> stays the entity tag of the stored bytes (closed by ADR 0032)** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0010 D2: A listing size is computed by arithmetic; a listing issues no per-object request** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0010 D3: Under a non-encrypting provider a listing reports the stored size verbatim** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0010 D4: A listing response is a real S3 document built explicitly by the proxy** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0011 D7: When the proxy drives the upload it picks its own parts, a multiple of the segment size** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Whether The New Line Carries backend_endpoint** (3 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **SSL_CERT_FILE And SSL_CERT_DIR Are Read By The Go TLS Stack** (3 connections) — `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- **ADR 0008 D10: The backend account identity never appears in a response document** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D11: A new pass-through of backend-supplied text is decided per element** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D12: A value the proxy does not have is omitted, never rendered as a zero value** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D12a: The proxy states its own request identifier on every answer it composes** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D2: Response bodies are marshalled from typed structures, never assembled from strings** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D3: Response documents carry the S3 names, root and namespace, and only vouchable elements** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **ADR 0008 D5: No trusted-proxy list guards the forwarded headers** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- *... and 39 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (8 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (7 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (5 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (5 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (5 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (5 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (5 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (5 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (4 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (2 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`

## Audit Trail

- EXTRACTED: 115 (83%)
- INFERRED: 24 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*