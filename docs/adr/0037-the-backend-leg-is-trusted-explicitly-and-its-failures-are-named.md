# ADR 0037: The backend leg is trusted explicitly, and its failures are named

## Status

Accepted. Date: 2026-09-18.

**Decided in the session that wrote this record; not yet built.** What exists today is
the failure classification and its counter, which this record narrows rather than
introduces. The trust configuration below — `ca_file` and its refusals — is new and
outstanding.

## Context

The proxy speaks to exactly one peer that is not a client: its S3 backend. Under this
project's threat model that backend is an adversary for the *object bytes* (ADR 0001),
which is why the stored format authenticates everything it hands back. Transport security
on that leg defends something else and narrower: it keeps a third party off the wire, and
it keeps the backend credential — which travels in a signature header on every request —
away from anybody listening.

Until now the proxy configured that leg with two values: the scheme in `target_endpoint`,
which decides whether TLS is used at all, and `insecure_skip_verify`, which decides whether
the certificate is checked. There was no third option. An operator whose backend presents a
certificate from a private certificate authority — which is what an enterprise backend
usually presents — had only mechanisms that belong to the Go runtime rather than to this
product: replace the image's certificate bundle, or point `SSL_CERT_FILE` at another file.
Both work. Neither is a configuration key, neither is validated, neither is mentioned
anywhere the operator looks, and both fail in a way that is indistinguishable from the
backend simply being broken.

The consequence was predictable and it is the reason this record exists: faced with a
connection that will not come up and no documented way to make it, an operator reaches for
`insecure_skip_verify`. The product offered exactly one visible answer to a trust problem,
and it was the one that removes the trust.

The second half of the problem is what the operator sees when it goes wrong. A transport
failure on this leg is reported: there is a log line per failed round trip naming a failure
class and the host, and a counter of failed round trips by class beside a counter of
answered ones, which is the surface an alert is written against (ADR 0034 D6). But one of
those classes, `tls`, holds two situations that demand opposite reactions. A certificate
that does not verify is a permanent state: no retry helps, no amount of waiting helps, a
person has to change something. A protocol-level handshake failure may be a version
mismatch that a restart or a peer upgrade resolves. Collapsed into one class, the first is
indistinguishable from the second at the only place an alert can look.

## Decision

**D1. A backend entry names its own trust.** The entry gains an optional `ca_file`: the
path to one PEM file, which may hold several certificates. It sits beside
`target_endpoint`, `region`, the credential pair and `insecure_skip_verify`, so trust is
configured per backend from the start and stays correct when more than one backend entry is
read.

**D2. `ca_file` replaces the system roots for that backend; it does not add to them.** When
it is set, that backend's chain is verified against the certificates in that file and
against nothing else. When it is absent, the system roots apply as before. The narrower
rule is the deliberate one: a backend under a private authority has no reason to also be
vouchable by the hundred and fifty public roots an image ships, and removing them from that
decision closes the mis-issuance path entirely rather than making it less likely.

**D3. A `ca_file` that cannot serve as a trust root refuses the start, and so does a
contradiction.** Two refusals, each naming the key and the entry it sits in:

- the file cannot be read, is empty, or holds no certificate. Falling back to the system
  roots here would *widen* trust in response to an error, silently, on the one path whose
  entire purpose is to narrow it. A startup refusal is the only answer that cannot be
  mistaken for success;
- `ca_file` and `insecure_skip_verify: true` are both set. These are two contradictory
  statements about the same trust, and there is no resolution that can be defended:
  honouring either one discards a value the operator wrote deliberately, and leaves them
  believing the connection behaves differently than it does.

**D4. The trust pool is built once, when the process starts.** A rotated authority
therefore takes a restart, and nothing in the product will say that a running process is
holding roots that have been replaced on disk. This is stated rather than solved: watching
a file for a security-relevant change is a mechanism with its own failure modes, and an
operator who rotates a certificate authority is performing a planned action that can carry
a restart.

**D5. The environment variables underneath are a mechanism, not an interface.**
`SSL_CERT_FILE` and `SSL_CERT_DIR` are read by the Go TLS stack, not by this product's
configuration loader, and they keep working exactly as they always have. They are not an
exception to the rule that the proxy reads no configuration key from the environment
(ADR 0013), because no key is what they carry. Where both apply, `ca_file` wins for its
backend, and it wins silently: a variable this product does not read is not a variable it
can refuse.

**D6. A certificate that does not verify is its own failure class.** The class set becomes
`dns`, `tls_certificate`, `tls`, `timeout`, `connect` and `other`. `tls_certificate` is the
subset whose cause is a failed certificate verification — an unknown authority, a name that
does not match, an expired or otherwise invalid certificate; `tls` keeps the protocol-level
remainder. The distinction appears in both channels, the log line and
`s3ep_backend_transport_failures_total`, because an alert can only read the second.

**D7. The certificate class is logged at error; the other transport classes stay at
warning.** The level is not a severity ranking, it is a statement about who has to act:
every other class can resolve without a person, and this one cannot.

**D8. The response a client receives does not change.** A backend the proxy cannot reach or
cannot verify is still answered `500 InternalError`. It is not a state of the object, so
the rule that makes an object-level refusal a 4xx does not reach it; S3 has no code that
means *the storage behind this endpoint is unusable*; and `503 ServiceUnavailable` would be
retried by a client SDK exactly as the 500 is, while promising a transience that a trust
misconfiguration does not have. The diagnosis belongs in the operator's channels, which is
what D6 and D7 make precise, and never in a response body (ADR 0008).

## Consequences

- An operator has a documented, validated way to trust a private authority, and it is a
  configuration key rather than a runtime variable — so it is in the key reference, it is
  checked at startup, and getting it wrong names itself.
- `insecure_skip_verify` stops being the only visible answer to a trust problem. It keeps
  its meaning and its warning; what changes is that the threat model can now name an
  alternative when it advises against it.
- The value set of the `class` label grows by one and the meaning of `tls` narrows. The
  label's values are an interface, so this is a documented change with an upgrade note,
  and anyone alerting on `class="tls"` specifically will stop seeing certificate failures
  there.
- Two configurations that ship in the repository stop demonstrating
  `insecure_skip_verify: true`: the demonstration stack verifies its backend for real,
  through `ca_file`, against the authority that issued its own test certificate. The
  examples an operator is most likely to copy stop teaching the insecure knob.
- A per-backend `ca_file` permits a deployment whose backends carry certificates from
  different private authorities. Nothing in this record assumes they do or do not.

## Alternatives Considered

**`ca_file` adds to the system roots instead of replacing them.** Friendlier, and wrong for
the case it exists to serve: it leaves every public authority able to vouch for a backend
that is deliberately private. Replacement is the whole benefit.

**A directory instead of a file.** `SSL_CERT_DIR` shows the shape and a scan is not hard.
Rejected because a secret mounted into a container arrives as a file, a PEM file already
concatenates, so a rotation overlap is two blocks in one file — and an empty or
mis-mounted directory produces an empty pool, which fails with exactly the message a
*missing* authority produces. That is a failure mode with no signature of its own.

**Let `insecure_skip_verify` win over `ca_file`, or the other way round, with a warning.**
Both were rejected in D3. A warning is what a running system emits about something it has
already decided; a contradiction in a trust declaration is something nobody should have
decided on the operator's behalf.

**Answer `503 ServiceUnavailable` instead of `500 InternalError`.** Rejected in D8: it
reads as transient to every retrying client, and the condition this record is about is the
opposite of transient.

**Leave the certificate case inside the `tls` class and carry the detail in the log text
only.** This is what the tree does today. Rejected because it makes the distinction
available only to a person reading prose, and the counter — not the log — is what ADR 0034
D6 designates as the thing an alert is written against.

**Probe the backend at startup or from the readiness endpoint so the failure is visible
before traffic arrives.** Out of scope here and largely already answered: a probe reports
the process and never its dependencies, and dependency health is reported without being
acted on (ADR 0034 D6, D9). Whether a non-probe startup *check* is worth its cost is a
separate decision, and ADR 0034 D9 names the condition under which it reopens.

## Residual risks

- **A rotated authority is served by a stale pool until someone restarts the process**
  (D4). The chart does not roll a pod when a volume the operator added changes, so nothing
  makes this visible either.
- **`ca_file` winning over `SSL_CERT_FILE` is silent** (D5). An operator who sets both, and
  expects the variable to win, has no signal. The documentation is the only mitigation.
- **The narrower trust is also a narrower blast radius for a mistake.** A `ca_file` naming
  the wrong authority fails closed, which is correct, but it fails closed for *every*
  request to that backend at once. The startup refusals in D3 catch a file that is unusable;
  they cannot catch a file that is valid and wrong.
- **A certificate failure is still retried to the SDK's attempt ceiling**, so one client
  request costs several handshakes and several log lines, none of which can succeed. This
  record does not change retry behaviour.

## References

* [ADR 0001](0001-the-backend-is-hostile.md) — the backend is an adversary for the object
  bytes; transport security on that leg defends something narrower
* [ADR 0008](0008-every-response-describes-the-proxy.md) — what never reaches a client
* [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) — a key exists only
  if code reads it, and an unworkable configuration refuses to start
* [ADR 0026](0026-the-proxy-terminates-tls-at-its-own-service.md) — the other TLS leg, the
  proxy's own listener
* [ADR 0030](0030-the-network-boundary-belongs-to-the-administrator.md) — the monitoring
  listener is unauthenticated, which bounds what a label may hold
* [ADR 0034](0034-a-probe-reports-the-process-never-its-dependencies.md) — dependency
  health is reported and never acted on; the counter pair is the alerting surface
* [docs/security/threat-model.md](../security/threat-model.md) — *Transport*
