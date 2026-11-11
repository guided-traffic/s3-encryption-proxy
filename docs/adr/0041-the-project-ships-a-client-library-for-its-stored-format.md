# ADR 0041: The project ships a client library for its stored format, and the library and the proxy share one implementation of it

## Status

**Accepted.** Date: 2026-11-11.

Implemented with this decision: the library is the Go package
`github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc`, first released with the release
cut from this change. The rules both sides apply live in one place, and the integration suite
proves on every release, over the plain-HTTP and the TLS endpoint, that the proxy reads what
the library wrote and the library reads what the proxy wrote.

## Context

On 2026-11-06 another Go program needed to store objects in this project's format without
sending them through the proxy: it holds the data already, and a second network hop to a proxy
next to it buys nothing but latency. It imported the proxy's encryption packages and added the
rest itself — drawing the data key, the four `s3ep-*` metadata keys, the prefix rule, the key
admission rules, the key ring by fingerprint, the S3 calls.

That worked, and it showed two problems that grow with every importer:

- **The format rules were written twice.** The codec and the key wrap were shared, but which
  keys an object carries, how the namespace is tested, what makes a key acceptable and how a
  stored length is checked against the trailer were re-implemented beside the proxy's own. A
  change on one side would not have reached the other, and nothing would have noticed.
- **Interoperability was proved only when someone moved a pin.** The importer required the
  proxy by release tag and ran its own interop test against a running proxy. A release that
  changed the format would have been noticed in the importer, by whoever bumped it next — not
  in the pull request that changed it.

## Decision

**D1. The project ships a client library.** A Go package in the proxy's own module writes and
reads the stored format, `s3ep-gcm-seg-v2`, directly against an S3 endpoint: a streamed upload
of a body of unknown length, a whole-object read, a ranged read, a read of the trailer alone,
and a re-encrypting copy. It is released with the proxy, under the proxy's version and module
path (ADR 0040).

**D2. The library and the proxy share one implementation of every format rule.** The codec, the
data key wrap, the four metadata keys and how they are built and read, the default prefix
`s3ep-` and the pattern a prefix must match, the namespace test, how a new object is keyed, the
admission rules for an `aes_key`, and the check of a trailer against the stored length are one
piece of code that both call. The library adds the S3 calls and its key ring and nothing else.
A rule only one of them applies is a defect.

**D3. Interoperability is proved on every pull request.** The integration suite writes through
the library and reads through the proxy, and the other way round, at sizes that take the
proxy's single-request path and its internal multipart producer, against both proxy endpoints.
The library's own behaviour against a hostile backend — a flipped byte, a removed segment, a
server-side copy, a forged wrapped key, a foreign object — is asserted in the same suite.

**D4. The library always encrypts and never passes an object through.** It holds `aes` keys
only: one active key that wraps every new object, and retired keys that open what they wrapped.
There is no `exit` mode. An object without the format's metadata is refused, not served; a
wrapped key that does not authenticate, or a fingerprint none of its keys carries, is refused as
a permanent state of that object.

**D5. The namespace is refused, not dropped.** A caller's user metadata key inside the prefix
fails the write before anything is stored, the same answer the proxy gives with
`400 InvalidArgument` (ADR 0009 D6).

**D6. A whole-object read is one request and is verified at its end.** The library does not
read the trailer first as the proxy does (ADR 0003 D14). Every byte it hands out is
authenticated, and the trailer — the plaintext length and the CRC32C — is checked when the body
ends, so a caller commits nothing before the read has reached its end. A read of the trailer
alone returns the authenticated length and checksum in one ranged request.

**D7. An upload sends no opportunistic request checksum.** The body is the ciphertext stream,
produced as the upload reads it and not seekable. A request checksum over it fails against a
plain-HTTP endpoint, costs a full extra pass against an HTTPS one, and covers nothing the format
does not. The proxy drops the same checksum on its backend leg for the same reason.

**D8. The library's Go interface is not a compatibility promise.** Under ADR 0018 D5 a change
to it is not a break and may ship in a minor release. Stored-data compatibility follows
ADR 0017: within a major, what one release writes the next reads.

## Consequences

- An application that uses the library holds the master key. Its process is inside the trust
  boundary in the same way the proxy is, and it bypasses every control the proxy applies to a
  client — authentication included.
- A change to a format rule is made once and reaches both sides in the same release. The
  integration suite fails the pull request that breaks interoperability, not the importer that
  upgrades later.
- The module requires the AWS SDK's `transfermanager`, a 0.x module, and the library's
  client interface is its client interface. The project's own tests upload through it too;
  the deprecated `manager` module it replaces is gone.
- An importer pins an exact version. A minor release can stop compiling against its code
  (D8), and crossing a major means rewriting the import path and accepting that the format may
  have changed (ADR 0017, ADR 0040).
- The proxy's own configuration, provider factory and the library refuse the same keys. A key
  the configuration would have refused was accepted by the provider factory before; the two now
  apply one rule.

## Alternatives Considered

**Keep the library in the importing program, required by tag.** That is how it began. Rejected:
the format rules exist twice, and interoperability is proved only when somebody moves the pin.

**A separate repository or module for the library.** Rejected for the reason ADR 0040 rejects a
separate module for the importable packages: a second release line, and two versions of the
format code that can build into one program.

**Send the application's traffic through a proxy.** Rejected for this case. The proxy is the
product for a client that cannot be changed; an application that can link a library pays a
network hop and an extra process for nothing.

**Make the library's Go interface a compatibility promise.** Rejected for now. The library and
the proxy share one release line, so a breaking change to the library's interface would force a
major release on every operator of the proxy, and under ADR 0017 a major announces a possible
break in the stored format that such a change does not make.

## Residual risks

- **The application holds the master key.** Nothing in the library limits what a process with
  the key can read or write; key isolation from the process is the gap ADR 0005 leaves open for
  the proxy too.
- **A caller that commits before the end of a read commits unverified data** (D6). The library
  states it; it cannot enforce it.
- **No rollback protection**, the same limit the proxy has: a backend that serves an older,
  genuine version of an object under the same key is not detected.
- **Listings report stored sizes.** The library converts them without a key; only a read of the
  trailer authenticates a length.
- **Verified 2026-11-11, locally only:** the integration suite, with the interop tests, passed
  against the demo stack over both proxy endpoints. The first run in continuous integration is
  the pull request that carries this decision.

## References

- ADR 0003 — Objects are an authenticated segment chain (D14 the tail-first read)
- ADR 0009 — The metadata prefix is the proxy's namespace (D1, D2, D6)
- ADR 0017 — Stored data compatibility is not owed
- ADR 0018 — A major release is declared by a label (D5 what a break is)
- ADR 0040 — The Go module path carries the release's major version
- [docs/operations/client-library.md](../operations/client-library.md) — using the library
- [docs/security/key-management.md](../security/key-management.md) — where the master key lives
