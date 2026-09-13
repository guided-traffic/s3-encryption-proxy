# Architecture Decision Records

Every durable design decision of this proxy lives here, one file per decision family. An ADR
records **what was decided, why, what was rejected, and what it costs** — so a later change can
argue with the decision instead of rediscovering it.

**An ADR is not a ticket.** A ticket is a work list: it exists while work is outstanding and is
**deleted** when the work lands. An ADR is the decision behind that work and stays. Nothing
outside `docs/tickets/` may reference a ticket — not the README, not the security architecture,
not a code comment, not a commit message. ADRs may be referenced from anywhere.

## Format

Filename: `NNNN-kebab-case-title.md`, numbered in the order they were written.

Sections, in this order:

| Section | Content |
|---|---|
| `# ADR NNNN: Title` | The decision as a title, not a topic |
| `## Status` | `Accepted` / `Superseded by ADR NNNN` / `Amended`, plus `Date:` and what is implemented versus still open |
| `## Context` | The forces and the concrete failure that made the decision necessary |
| `## Decision` | `D1 … Dn`, each a rule that holds going forward, in present tense |
| `## Consequences` | What this costs, including the parts nobody likes |
| `## Alternatives Considered` | Each option and why it lost |
| `## Residual risks` | Accepted risks, open items, and what was **not** verified |
| `## References` | Sibling ADRs and user-facing documents |

## Ground rules

- **English only.**
- **A decision, not an implementation.** An ADR states what the product does and why. It carries
  **no references into the code**: no file paths, no line numbers, no function, type or package
  names, and no links into the tree. A reader must be able to act on the decision without opening
  the repository, and the ADR must not go stale when a file is renamed.
- **The product's own vocabulary is not a code reference.** Configuration keys
  (`encryption.metadata_key_prefix`), stored metadata keys (`s3ep-kek-fingerprint`), S3 error
  codes (`InvalidObjectState`), header names and algorithm names are the interface the decision is
  about. Name them exactly.
- **Say what is decided, and separately what is built.** The `Status` section carries the
  implementation state; the `Decision` section is written in the present tense either way.
- **Mark what was not verified.** An assumption never travels as a fact.

## Keeping them current

**An ADR is part of the product, not a historical note.** When a decision changes, the ADR is
updated in the same change — the `Decision` section states the new rule, the `Status` section
records the amendment with its date, and the superseded rule is marked in place rather than
deleted. A reader must never find the old rule stated as current.

A configuration key or a name the product has since removed stays in the record wherever the
decision names it; the `Status` section is where a reader learns it is gone. A new record is added
to the index below in the same change that writes it.

## Index

Every record here is **Accepted**; none is superseded. The *State* column is the coarse build
state as of 2026-09-13, on the unreleased 5.0.0 branch: **Implemented**, **Partly built** (some
rules of the decision hold, the rest are decided and outstanding) or **Not built** (decided,
nothing of it exists yet). A state that reads *Implemented, except …* names what is still
outstanding. The record's own `Status` section says which rule is which and is the authority;
this column is a reading aid.

### Foundations

| ADR | Decision | State |
|---|---|---|
| [0001](0001-the-backend-is-hostile.md) | The S3 backend is an adversary; only the proxy's own verification counts, and integrity is not configurable | Implemented |
| [0006](0006-the-proxy-serves-any-s3-client.md) | Any S3 client is in scope; compatibility is argued from S3 semantics, never from one observed client | Partly built |

### Stored format

| ADR | Decision | State |
|---|---|---|
| [0002](0002-one-data-key-per-object.md) | One random data key per object, wrapped by the configured key encryption key and carried in the object's own metadata | Implemented |
| [0003](0003-objects-are-an-authenticated-segment-chain.md) | Objects are a chain of AES-256-GCM segments plus an authenticated trailer; no byte is served unverified | Implemented, except D9's request count for a suffix or open-ended range |
| [0004](0004-one-local-key-provider.md) | One local key provider: base64 of 32 random bytes, an authenticated wrap, a derived fingerprint, no passphrases | Implemented |
| [0005](0005-a-kms-key-is-a-provider.md) | A key held in a KMS is a provider type of its own; delivering a local key from a secret store is not a KMS | Not built |
| [0009](0009-the-metadata-prefix-is-the-proxys-namespace.md) | The configured metadata prefix is the proxy's exclusive namespace: a client write into it is refused, and it never appears in a response | Implemented |
| [0023](0023-filename-encryption-encrypts-directory-segments.md) | If filename encryption ships it encrypts directory segments only, deterministically, with no mapping index | Not built |
| [0025](0025-leaving-is-a-supported-mode.md) | Leaving is a supported mode: the exit provider needs no licence, writes plaintext and still decrypts what was encrypted before the switch | Implemented |

### The S3 surface

| ADR | Decision | State |
|---|---|---|
| [0007](0007-forward-it-or-refuse-it.md) | Forward it or refuse it with a named S3 error; never accept, discard and answer success | Implemented, except D1's six response-header overrides on a `GET`, D7 on the proxy's own multipart upload and D8's answer to `?restore` |
| [0008](0008-every-response-describes-the-proxy.md) | Every response is composed by the proxy — status, code, headers and body — and never echoes the backend | Implemented, except D12's single timestamp renderer (one format in four places), D3's S3 namespace on five documents and D10 on the access-control documents |
| [0010](0010-sizes-and-listings-describe-the-plaintext.md) | Every reported size and every listing describes the plaintext, computed without a per-object round trip | Implemented, except D7's refusal of an unknown `encoding-type` and a `KeyCount` still forwarded from the backend |
| [0011](0011-the-proxy-owns-the-part-layout.md) | The proxy fixes the part layout it writes, refuses one it cannot verify, and refuses server-side copy | Implemented |
| [0012](0012-client-checksums-are-verified-never-forwarded.md) | Every checksum a client declares is verified against the plaintext, never forwarded to the backend and never stored; the proxy serves its own sealed CRC32C on whole-object reads | Implemented |
| [0024](0024-an-upload-forwards-while-it-receives.md) | An upload forwards bytes while it is still receiving them; no write path waits for a complete object before it begins sending it | Implemented, except D5's replay of a retained part |

### Operation

| ADR | Decision | State |
|---|---|---|
| [0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) | A configuration key exists only if code reads it; an unworkable configuration refuses to start | Implemented, except four of D7's zero cases |
| [0014](0014-authentication-is-sigv4-no-rate-limiting.md) | SigV4 in both forms against static configured clients; no rate limiting and no per-address blocking | Implemented |
| [0015](0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) | No wall clock on a transfer; only the header phase, the idle connection and shutdown are bounded | Implemented, except D4's "no other fixed shutdown deadline" for the monitoring and profiling listeners |
| [0016](0016-the-license-is-a-startup-gate.md) | The license is a fatal startup gate, an explicit expiry claim is mandatory, and the expiry is discovered by a build | Partly built |
| [0021](0021-key-material-is-generated-never-committed.md) | No working key material or license token in the repository: generated on demand, injected through the environment | Partly built |
| [0030](0030-the-network-boundary-belongs-to-the-administrator.md) | The network boundary is the administrator's: the chart ships no network policy, and the unauthenticated monitoring listener is fenced by the cluster or not at all | Implemented |

### Process

| ADR | Decision | State |
|---|---|---|
| [0017](0017-stored-data-compatibility-is-not-owed.md) | No compatibility is owed for data at rest; a major release may break the format, and there is no migration: the data is uploaded again from its source | Partly built |
| [0018](0018-a-major-release-is-declared-by-a-label.md) | Releases are computed from the commits that reach `main`; a major requires a deliberate label on the pull request | Implemented |
| [0019](0019-integration-and-e2e-tests-are-the-product.md) | The integration and end-to-end suites are part of the product and are never skipped, weakened or disarmed | Partly built |
| [0020](0020-performance-is-measured-before-and-after.md) | Every performance claim carries a before-and-after measurement, taken locally on one machine; continuous integration measures once and never fails on a performance number | Partly built |
| [0022](0022-tickets-are-work-lists-that-get-deleted.md) | Tickets are deleted when the work lands; every durable decision lives in an ADR, and nothing outside the ticket directory cites a ticket | Partly built |
| [0026](0026-the-proxy-terminates-tls-at-its-own-service.md) | The chart gives the proxy its own TLS listener for the in-cluster Service, with a certificate it issues or one the operator brings | Implemented |
| [0027](0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md) | One backend-agnostic conformance suite runs free against the local stack and on a schedule against a paid backend; the corpus is seeded once and a byte budget is enforced in code | Implemented |
| [0028](0028-an-abandoned-upload-is-ended-not-forgotten.md) | A client-driven multipart upload expires on inactivity, not on age, and the sweeper aborts it at the backend before it forgets it | Implemented |
| [0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md) | Graceful shutdown goes readiness-false, stop accepting, finish what is running, then end every upload that can no longer be finished | Implemented |

## Related documents

* [README.md](../../README.md) — user-facing reference
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model, trust boundaries and the hardening checklist
* [docs/developer/README.md](../developer/README.md) — how the subsystems work; the home for everything an ADR may not name
* [CLAUDE.md](../../CLAUDE.md) — project conventions, the ticket lifecycle and the ADR obligation
