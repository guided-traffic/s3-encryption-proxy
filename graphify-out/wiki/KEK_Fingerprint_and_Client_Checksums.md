# KEK Fingerprint and Client Checksums

> 39 nodes · cohesion 0.06

## Key Concepts

- **ADR 0012 Client checksums are verified, never forwarded** (39 connections) — `DEVELOPER.md`
- **ADR 0012 D3: Every checksum the client declares is verified, unconditionally** (5 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Verification Against the Plaintext Payload** (5 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0004 D6: Fingerprint and wrapping key are derived with HKDF-SHA256 under distinct labels** (4 connections) — `docs/adr/0004-one-local-key-provider.md`
- **HKDF Labels and Wrap Associated Data Are Fixed Format Constants** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **s3ep-kek-fingerprint** (3 connections) — `docs/adr/0004-one-local-key-provider.md`
- **ADR 0010 D5: No listing entry carries a checksum element** (3 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0012 D10: The proxy serves its own sealed CRC32C on a whole-object GET and on HEAD** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D12: An upload is checked against the declared length; a short body is a failed request** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D2: Verification applies to every request that carries a body, on every write path** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D6: A mismatch answers 400 BadDigest; a malformed value answers 400 InvalidDigest** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Sealed Plaintext CRC32C (x-amz-checksum-crc32c)** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0013 D9a: clean_aws_signature_v4_chunked is deleted: no value an operator may set is acceptable** (3 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **ADR 0005 D8: The published fingerprint identifies the key's address, not its material** (2 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **s3ep-kek-fingerprint (the one fingerprint not derived from key material)** (2 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **No Checksum Element in a Listing** (2 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **ADR 0012 D1: A client checksum is verified against the plaintext payload, framing stripped** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D10a: The served value is recorded at upload, never computed from the bytes about to be sent** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D14: The multi-object delete must carry a body digest or is refused 400 InvalidRequest** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D4: (struck) The cryptographic digests were to be gated behind a configuration key** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D5: A checksum named in X-Amz-Trailer that never arrives is a failed verification** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D8: No client checksum value is ever sent to the backend** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **ADR 0012 D9: No checksum of the plaintext is ever written to object metadata** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **No Plaintext Checksum in Object Metadata (confirmation oracle)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **optimizations.clean_aws_signature_v4_chunked (removed)** (2 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- *... and 14 more nodes in this community*

## Relationships

- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (6 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (4 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (3 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (3 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (3 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (3 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (2 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (2 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (1 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (1 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)

## Source Files

- `DEVELOPER.md`
- `docs/adr/0004-one-local-key-provider.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md`

## Audit Trail

- EXTRACTED: 72 (94%)
- INFERRED: 5 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*