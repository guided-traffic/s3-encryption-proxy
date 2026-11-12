# ADR 0003: Objects are an authenticated segment chain

> God node · 88 connections · `README.md`

**Community:** [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md)

## Connections by Relation

### cites
- [ADR 0013: A configuration key exists only if code reads it](ADR_0013-_A_configuration_key_exists_only_if_code_reads_it.md) `EXTRACTED`
- ADR 0001: The backend is hostile `EXTRACTED`
- ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt `EXTRACTED`
- Developer guide (DEVELOPER.md) `EXTRACTED`
- ADR 0017: Stored data compatibility is not owed `EXTRACTED`
- ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded `EXTRACTED`
- ADR 0019: Integration and e2e tests are the product `EXTRACTED`
- ADR 0025: Leaving is a supported mode `EXTRACTED`
- ADR 0002: One data key per object `EXTRACTED`
- ADR 0020: Performance is measured before and after `EXTRACTED`
- ADR 0018: A major release is declared by a label `EXTRACTED`
- ADR 0005: A KMS key is a provider `EXTRACTED`
- ADR 0004: One local key provider `EXTRACTED`
- Ticket 037: Several backends kept in sync with integrity fallback `EXTRACTED`
- ADR 0009: The metadata prefix is the proxy namespace `EXTRACTED`
- ADR 0006: The proxy serves any S3 client `EXTRACTED`
- ADR 0023: Filename encryption encrypts every segment with a searchable leaf head `EXTRACTED`
- ADR 0010: Sizes and listings describe the plaintext `EXTRACTED`
- ADR 0027: Conformance is asserted against a backend that is not MinIO, seeded once and bounded by a byte budget `EXTRACTED`
- ADR 0032: The entity tag is a change token `EXTRACTED`
- *…and 26 more `cites` connection(s) not listed (lowest-degree first to go)*

### conceptually_related_to
- Out-of-band recovery tool for damaged objects `INFERRED`
- Segment Chain Model 3.4x Faster (cipher only) `INFERRED`
- A part is an independent slice of the segment chain `INFERRED`

### implements
- Per-segment authentication contains damage to one segment `INFERRED`

### references
- Architecture Decision Records index (docs/adr/README.md) `EXTRACTED`
- Operations: S3 API behaviour `EXTRACTED`
- Stored objects: what is written, what it guarantees, what leaks `EXTRACTED`
- What the proxy guarantees about your bytes `EXTRACTED`
- Operations: Upgrading `EXTRACTED`
- CRC32C over whole plaintext sealed in trailer (D13) `EXTRACTED`
- Sealed trailer with plaintext length and CRC32C `EXTRACTED`
- s3ep-gcm-seg-v2 AES-256-GCM segment chain `EXTRACTED`
- Tail-first whole-object read and x-amz-checksum-crc32c `EXTRACTED`
- Foreign-format objects are refused, never guessed at (D4) `EXTRACTED`
- Read fallback to another backend on integrity refusal `EXTRACTED`
- Associated data binds format id, object key and segment index `EXTRACTED`
- s3ep-dek-algorithm metadata key `EXTRACTED`
- 64 KiB segment size, a format constant `EXTRACTED`
- Size function well-formedness guard (D12a) `EXTRACTED`
- Wrapped key auth failure answers 403 InvalidObjectState `EXTRACTED`
- Bucket not in associated data `EXTRACTED`
- Foreign object refused: 403 InvalidObjectState 'Object is not encrypted by this proxy' `EXTRACTED`
- Integrity not configurable (no integrity mode) `EXTRACTED`
- Plaintext length is a pure function of stored length `EXTRACTED`
- *…and 18 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*