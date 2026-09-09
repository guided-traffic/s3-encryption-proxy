# Forward It Or Refuse It

> 10 nodes · cohesion 0.24

## Key Concepts

- **Forward It or Refuse It, Never Silently Drop It** (10 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Every Declared Client Checksum Is Verified Against the Plaintext** (4 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **The Proxy Serves Any S3 Client** (3 connections) — `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- **SSE-C Refused With 501 Until Every Verb Carries the Key** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **A Client Metadata Key Inside the Namespace Is Refused** (2 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **SigV4 in Both Forms Against Static Configured Clients** (2 connections) — `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- **Uniform Storage-Header Forwarding on Every Upload Path** (1 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **Listing Parameters Honoured or Refused, max-keys Validated** (1 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **Multi-Object Delete Must Carry a Verified Body Digest** (1 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **The Integration Suite Runs Over Both Plain HTTP and TLS** (1 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`

## Relationships

- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (2 shared connections)
- [ADR Authoring Rules](ADR_Authoring_Rules.md) (1 shared connections)
- [Major Release Label Policy](Major_Release_Label_Policy.md) (1 shared connections)
- [One Data Key Per Object](One_Data_Key_Per_Object.md) (1 shared connections)

## Source Files

- `docs/adr/0006-the-proxy-serves-any-s3-client.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`

## Audit Trail

- EXTRACTED: 15 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*