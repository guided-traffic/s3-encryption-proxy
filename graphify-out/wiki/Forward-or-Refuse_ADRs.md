# Forward-or-Refuse ADRs

> 31 nodes · cohesion 0.07

## Key Concepts

- **ADR 0007: Forward It or Refuse It, Never Silently Drop It** (27 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Honour It or Refuse It with a Named S3 Error (D1)** (6 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **A Configuration Key Exists Only If Code Reads It (D1)** (5 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **A Control That Exists Only in Configuration Is Worse Than None (D6)** (4 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **All Three Write Paths Produce the Identical Byte Layout (D11)** (3 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **A Backend Error Behind a Non-Error Status Is a Failure (D11)** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Anything That Does Not Touch Object Content Is Forwarded (D2)** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Every Upload Path Forwards the Same Storage Headers (D3)** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Every Failure the Client Sees Is an S3 <Error> Document (D7)** (3 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **A Client Metadata Key Inside the Namespace Is Refused (D6)** (3 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **A Multipart Completion Is Final: No Post-Completion Rewrite (D8)** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Every Checksum the Client Declares Is Verified, Unconditionally (D3)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **No Client Checksum Value Is Ever Sent to the Backend (D8)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **What the Backend Learns Anyway (D8)** (2 connections) — `docs/adr/0001-the-backend-is-hostile.md`
- **Compatibility Is Argued from S3 Semantics, Never from One Client (D2, D3)** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **Support Is Claimed Only As Far As It Is Exercised (D7)** (2 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **A Refusal Says What Is True (D8)** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **PUT ?acl and PUT ?cors Carry Their Document in Full (D5)** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Conditional Request Headers Are Honoured (D7)** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Forwarded Tags and User Metadata Are a Plaintext Index at the Backend (D12)** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Object Tagging, Retention and Legal-Hold Are Passthrough (D4)** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Response Bodies Are Marshalled from Typed Structures (D2)** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **HEAD /{bucket} Is a Bucket Existence Check (D10)** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **Every Listing Parameter Is Honoured or Refused; max-keys Validated (D7, D8, D9)** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **No Listing Entry Carries a Checksum Element (D5)** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- *... and 6 more nodes in this community*

## Relationships

- [Authentication and Response ADRs](Authentication_and_Response_ADRs.md) (26 shared connections)
- [Developer Docs: Errors and Format](Developer_Docs-_Errors_and_Format.md) (7 shared connections)
- [Key Management ADRs](Key_Management_ADRs.md) (2 shared connections)

## Source Files

- `docs/adr/0001-the-backend-is-hostile.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`

## Audit Trail

- EXTRACTED: 64 (93%)
- INFERRED: 5 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*