# ADR 0013: A configuration key exists only if code reads it

> God node · 71 connections · `docs/tickets/037-multiple-backends.md`

**Community:** [SigV4 Authentication Rules](SigV4_Authentication_Rules.md)

## Connections by Relation

### cites
- [ADR 0003: Objects are an authenticated segment chain](ADR_0003-_Objects_are_an_authenticated_segment_chain.md) `EXTRACTED`
- ADR 0007: Forward it or refuse it `EXTRACTED`
- ADR 0001: The backend is hostile `EXTRACTED`
- ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt `EXTRACTED`
- Developer guide (DEVELOPER.md) `EXTRACTED`
- ADR 0017: Stored data compatibility is not owed `EXTRACTED`
- ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded `EXTRACTED`
- ADR 0014: Authentication is SigV4, no rate limiting `EXTRACTED`
- ADR 0019: Integration and e2e tests are the product `EXTRACTED`
- ADR 0008: Every response describes the proxy `EXTRACTED`
- ADR 0025: Leaving is a supported mode `EXTRACTED`
- ADR 0018: A major release is declared by a label `EXTRACTED`
- ADR 0005: A KMS key is a provider `EXTRACTED`
- ADR 0034: A probe reports the process, never its dependencies `EXTRACTED`
- ADR 0004: One local key provider `EXTRACTED`
- Ticket 037: Several backends kept in sync with integrity fallback `EXTRACTED`
- ADR 0009: The metadata prefix is the proxy namespace `EXTRACTED`
- ADR 0006: The proxy serves any S3 client `EXTRACTED`
- ADR 0023: Filename encryption encrypts every segment with a searchable leaf head `EXTRACTED`
- Helm chart README `EXTRACTED`
- *…and 24 more `cites` connection(s) not listed (lowest-degree first to go)*

### references
- Architecture Decision Records index (docs/adr/README.md) `EXTRACTED`
- Threat model and trust boundaries `EXTRACTED`
- D7 unworkable configuration refuses to start, never repaired `EXTRACTED`
- A key exists only if code reads it and the read changes behaviour `EXTRACTED`
- /livez liveness is a constant success (D2) `EXTRACTED`
- S3EP_AES_KEY environment variable reference (D3) `EXTRACTED`
- Proposed high_availability configuration block (question 37) `EXTRACTED`
- Six dead s3_security keys and per-address failure accounting deleted `EXTRACTED`
- D5 plain-HTTP backend refused under every provider `EXTRACTED`
- D8 pprof on its own loopback listener `EXTRACTED`
- Removed configuration keys refused by name, no deprecation window (D7) `EXTRACTED`
- optimizations.multipart_session_max_age refuses the start (D6) `EXTRACTED`
- s3_backends list shape shipped in 5.0.0, one entry read `EXTRACTED`
- D9a aws-chunked decoding unconditional `EXTRACTED`
- D13 license_file accepted and ignored `EXTRACTED`
- D14 no command-line flag overrides a key; only --config `EXTRACTED`
- s3_security.max_presign_expiry_seconds exists and is enforced at use `EXTRACTED`
- s3_backends is a list; exactly one entry read `EXTRACTED`
- D11 unknown configuration key refuses the start, naming it `EXTRACTED`
- An invalid configuration value refuses the start, naming the field (D8) `EXTRACTED`
- *…and 7 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*