# Proxy-Describing Responses

> 11 nodes · cohesion 0.20

## Key Concepts

- **Every Response Is Composed by the Proxy** (5 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **An Unworkable Configuration Refuses to Start** (5 connections) — `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- **The Metadata Prefix Is the Proxy's Exclusive Namespace** (4 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **Listings Are Real S3 Documents Built by the Proxy** (4 connections) — `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- **No Client Checksum Reaches the Backend, No Plaintext Checksum in Metadata** (3 connections) — `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- **Filename Encryption Encrypts Directory Segments Only** (3 connections) — `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- **An Error Behind a Non-Error Status Becomes 500** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **The Backend Account Never Appears in a Response** (2 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`
- **Prefix Shape Rule ^[a-z0-9][a-z0-9-]{2,}-$** (2 connections) — `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- **An Object Is Readable From Itself** (1 connections) — `docs/adr/0002-one-data-key-per-object.md`
- **The Multipart <Location> Names the Proxy, Not the Backend** (1 connections) — `docs/adr/0008-every-response-describes-the-proxy.md`

## Relationships

- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (4 shared connections)
- [Forward It Or Refuse It](Forward_It_Or_Refuse_It.md) (2 shared connections)
- [One Data Key Per Object](One_Data_Key_Per_Object.md) (1 shared connections)
- [Major Release Label Policy](Major_Release_Label_Policy.md) (1 shared connections)
- [SigV4 Without Rate Limiting](SigV4_Without_Rate_Limiting.md) (1 shared connections)
- [One Local Key Provider](One_Local_Key_Provider.md) (1 shared connections)

## Source Files

- `docs/adr/0002-one-data-key-per-object.md`
- `docs/adr/0008-every-response-describes-the-proxy.md`
- `docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md`
- `docs/adr/0010-sizes-and-listings-describe-the-plaintext.md`
- `docs/adr/0012-client-checksums-are-verified-never-forwarded.md`
- `docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`

## Audit Trail

- EXTRACTED: 19 (90%)
- INFERRED: 2 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*