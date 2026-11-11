# ADR 0003: Objects are an authenticated segment chain

> God node · 70 connections · `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`

**Community:** [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md)

## Connections by Relation

### cites
- ADR 0013: A configuration key exists only if code reads it `EXTRACTED`
- S3 Encryption Proxy README `EXTRACTED`
- Developer guide (DEVELOPER.md) `EXTRACTED`
- CLAUDE.md AI coding instructions `EXTRACTED`
- ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt `EXTRACTED`
- ADR 0001: The S3 backend is hostile `EXTRACTED`
- ADR 0017: Stored data compatibility is not owed `EXTRACTED`
- ADR 0019: Integration and e2e tests are the product `EXTRACTED`
- ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded `EXTRACTED`
- ADR 0020: Performance is measured before and after `EXTRACTED`
- ADR 0010: Sizes and listings describe the plaintext `EXTRACTED`
- ADR 0025: Leaving is a supported mode `EXTRACTED`
- ADR 0006: The proxy serves any S3 client `EXTRACTED`
- ADR 0018: A major release is declared by a label `EXTRACTED`
- Ticket 037: Several backends kept in sync with integrity fallback `EXTRACTED`
- ADR 0002: One data key per object `EXTRACTED`
- ADR 0004: One local key provider `EXTRACTED`
- ADR 0005: A KMS key is a provider `EXTRACTED`
- ADR 0009: The metadata prefix is the proxy namespace `EXTRACTED`
- ADR 0023: Filename encryption of key segments `EXTRACTED`
- *…and 30 more `cites` connection(s) not listed (lowest-degree first to go)*

### conceptually_related_to
- Out-of-band recovery tool for damaged objects `INFERRED`
- Segment Chain Model 3.4x Faster (cipher only) `INFERRED`

### implements
- Per-segment authentication contains damage to one segment `INFERRED`

### references
- s3ep-gcm-seg-v2 AES-256-GCM segment chain `EXTRACTED`
- Read fallback to another backend on integrity refusal `EXTRACTED`
- Sealed trailer with plaintext length and CRC32C `EXTRACTED`
- s3ep-dek-algorithm metadata key `EXTRACTED`
- Tail-first whole-object read and x-amz-checksum-crc32c `EXTRACTED`
- x-amz-checksum-crc32c answered on writes `EXTRACTED`
- Fail closed on foreign objects (403 InvalidObjectState) `EXTRACTED`
- Associated data binds format id, object key and segment index `EXTRACTED`
- Plaintext length is a pure function of stored length `EXTRACTED`
- Streaming read truncates on mid-stream fault; s3ep_object_integrity_failures_total `EXTRACTED`
- Wrapped key auth failure answers 403 InvalidObjectState `EXTRACTED`
- Listing Size Computed by Arithmetic on Stored Size (D2) `EXTRACTED`
- Uniform Segment-Aligned Parts (D2/D3) `INFERRED`
- All three write paths produce identical byte layout `EXTRACTED`
- Random 96-bit inline nonce per segment `EXTRACTED`
- Ranged read fetches only covered segments `EXTRACTED`
- 64 KiB segment size, a format constant `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*