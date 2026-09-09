# One Data Key Per Object

> 10 nodes · cohesion 0.22

## Key Concepts

- **A KMS-Backed KEK Is Its Own Provider Type** (5 connections) — `docs/adr/0005-a-kms-key-is-a-provider.md`
- **Associated Data Binds Format Id, Client Object Key and Index** (4 connections) — `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- **Content-Keyed DEK Cache** (3 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Server-Side Copy Refused With 422 NotSupportedWithEncryption** (3 connections) — `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- **Performance Is Measured Before and After, Never Asserted** (3 connections) — `docs/adr/0020-performance-is-measured-before-and-after.md`
- **AES-SIV-CMAC Name Transform With Parent-Chain AAD** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **The Name Transform Lives at the Backend Boundary** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **Key Rotation Is a Configuration Procedure** (2 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **Profiling on Its Own Loopback Listener** (1 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **Response Wrappers Preserve Flush, Hijack and ReaderFrom** (1 connections) — `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`

## Relationships

- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (3 shared connections)
- [Major Release Label Policy](Major_Release_Label_Policy.md) (2 shared connections)
- [SigV4 Without Rate Limiting](SigV4_Without_Rate_Limiting.md) (1 shared connections)
- [Forward It Or Refuse It](Forward_It_Or_Refuse_It.md) (1 shared connections)
- [Proxy-Describing Responses](Proxy-Describing_Responses.md) (1 shared connections)

## Source Files

- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0003-objects-are-an-authenticated-segment-chain.md`
- `docs/adr/0005-a-kms-key-is-a-provider.md`
- `docs/adr/0011-the-proxy-owns-the-part-layout.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md`
- `docs/adr/0020-performance-is-measured-before-and-after.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`

## Audit Trail

- EXTRACTED: 12 (67%)
- INFERRED: 6 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*