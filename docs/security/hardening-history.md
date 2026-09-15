# Hardening history — the closed items

The residual-risk checklist of
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) carries the items
that are **open**. This page carries the eight that are **closed**, in the order
they were closed, and it is history rather than a current rule: nothing here
states what the product does today. The section that does is section 8 of that
document.

**They are kept rather than deleted for two reasons.** What a defect was is how
you tell whether it came back — several of these are the reason a rule in the
threat model reads the way it does. And the numbers are identifiers: H-5 is H-5
whether it is open or closed, so an item that moves here keeps the name an older
report or commit message used.

The eight were closed by the segment chain, the derived fingerprint, the exit
provider, the three configuration decisions that were specified and then built,
and the removal that deleted the replaced format's read path along with every
configuration key no code reads.

> This page names files and functions on purpose, the way a developer page does,
> so it goes stale when the tree moves. A claim here describes the tree at the
> date the item was closed.

## H-10 Three configuration decisions are specified and not built — closed

**ADR 0013, ADR 0014. Closed 2026-09-11.**

All three landed. Recorded rather than deleted, because each changes what an
operator's existing configuration does:

| Decision | Now |
|---|---|
| `s3_security.max_clock_skew_seconds` governs both authentication forms (ADR 0013 D3, ADR 0014 D4) | It does. A configuration that narrows the window narrows it for every request, so **a client whose clock is off by more than the configured value starts being refused where it was accepted** — the one change in this family that can break a healthy deployment ([SECURITY_ARCHITECTURE.md § 6.3](../../SECURITY_ARCHITECTURE.md#63-the-clock-skew-window)) |
| `s3_security.max_presign_expiry_seconds`, default 3600 s, hard cap 7 days (ADR 0013 D6, ADR 0014 D5) | The key exists. A pre-signed URL may declare at most one hour by default, and the S3 maximum of seven days is the ceiling the setting may not exceed. A client that mints longer URLs needs it raised |
| The proxy refuses to start on a plain-`http://` backend endpoint under every provider (ADR 0013 D5, amended 2026-09-12) | The refusal is in configuration validation, so it fires before a listener or an S3 client exists. A scheme-less endpoint is refused with it. The `exit` provider is no longer the exception it was: there the object bytes travel in the clear as well, so plain HTTP exposes strictly more than it does under an encrypting provider |

- [x] ADR 0013 D3: honour `max_clock_skew_seconds` on the header-signed path
- [x] ADR 0013 D6: add `s3_security.max_presign_expiry_seconds`
- [x] ADR 0013 D5: refuse to start on a plain-HTTP backend under every provider
- [x] ADR 0013 D5, amended 2026-09-12: the `exit` provider is refused with the
      rest rather than warned about — there the object bytes travel in the clear
      to the backend beside the credential, the bucket names and the object keys
- [x] Meanwhile: terminate TLS on the backend endpoint — now enforced under
      every provider rather than advised

---

## H-11 The pass-through provider was not a pass-through above one part — **closed**

**Closed by the exit provider.** All three write paths now pass through, and the
read paths decide per object instead of on the active provider: the single
request ([operations.go:437-442](../../internal/proxy/handlers/object/operations.go#L437)),
the proxy's own multipart producer
([operations.go:875](../../internal/proxy/handlers/object/operations.go#L875)) and a
client-driven upload
([create.go:89-93](../../internal/proxy/handlers/multipart/create.go#L89),
[upload.go:109-118](../../internal/proxy/handlers/multipart/upload.go#L109),
[complete.go:178-195](../../internal/proxy/handlers/multipart/complete.go#L178)); `GET`
([operations.go:52-56](../../internal/proxy/handlers/object/operations.go#L52)), a
ranged `GET` ([range.go:167-183](../../internal/proxy/handlers/object/range.go#L167))
and `HEAD` ([operations.go:515-519](../../internal/proxy/handlers/object/operations.go#L515))
each read the object's own metadata.

What it was: `type: "none"` passed through only a `PUT` that fitted one backend
request. A larger or undeclared `PUT`, and any client-driven multipart upload,
sealed the object as a segment chain and stored its data key **unwrapped** in
`s3ep-encrypted-dek`, because `EncryptDEK` returned the key unchanged for that
provider. The read path then decided on the provider before it looked at the
object and handed the sealed bytes back, while `HEAD` reported the plaintext
size — the two disagreed about the same object, and a large object written that
way was not readable through the proxy at all. The key also sat next to the data,
unwrapped, on an object the metadata described as encrypted.

Both halves of that are gone: nothing is sealed under `exit`, so no data key is
drawn to leave lying about, and `EncryptDEK` no longer returns a key at all — it
returns an error, on the reasoning in [SECURITY_ARCHITECTURE.md § 3.2.1](../../SECURITY_ARCHITECTURE.md#321-what-the-exit-provider-means-for-this-threat-model).

- [ ] Under `exit` an object written before the switch and an object written
      after it are told apart by metadata alone. An operator who switches back to
      an encrypting provider makes everything written during the exit period
      foreign, and it is refused on read — plan the direction of travel before
      the switch

---

## H-1 Ranged reads are not verified by the proxy — **closed**

**Closed by ADR 0003.** A ranged read opens only the segments its window covers,
each under its own tag, so a partial read is authenticated exactly like a whole
one. Measured against a running stack: a range over a tampered segment delivers
nothing and the body is aborted
([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: the integrity value covered the whole object, so it could not be
checked against part of it. A ranged read was therefore authenticated by the
backend and by TLS — that is, by the adversary — and kopia, which is how Velero
stores volume data, reads its pack blobs exactly that way. Entire restores ran on
reads the proxy did not verify.

**What a ranged read still does not tell you**, and this is inherent to any
per-segment format rather than a defect to close:

- It authenticates only the segments in its window. Damage elsewhere in the
  object is invisible to it, and a client that only ever reads ranges never
  checks the object as a whole. Pinned by a test so that nobody "fixes" it by
  reading more than was asked for.
- A range that does not reach the end of the object never sees the trailer, so it
  cannot check the object's authenticated total length; for the object's size it
  trusts what the backend reports.

- [ ] A client that needs whole-object assurance must read the object whole; a
      ranged read is not a cheap substitute for that

---

## H-5 A tampered object is delivered, not refused — **closed**

**Closed by ADR 0003.** A modified object is never delivered whole, measured
against a running stack across six attacks: a flipped bit in the first segment,
in a middle segment and in the trailer, two segments swapped, a truncation and an
extension. The three the trailer proves — truncation, extension and a damaged
trailer — are refused with `403 InvalidObjectState` before the response begins
and nothing is written at all; the other three abort the body, and the prefix the
client did receive is byte-identical to the object's own opening plaintext
([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: the integrity value was verified after the last plaintext byte had
already been written to the client, and it was not verified at all when the
backend answered without a `Content-Length` — a header the backend chooses. No
setting refused tampered data; `strict` was `lax` with a different log line.

**The knob that appeared to control it is gone**, and that is the second half of
this item. `encryption.integrity_verification` and the four modes it selected —
`off`, `lax`, `strict`, `hybrid` — no longer exist: not in
`internal/config/config.go`, not in any shipped example, not in the chart values.
Verified by grep over the tree. Nothing in the product now offers a choice about
integrity, because there is no longer a choice to offer: the tag on each segment
is produced by the same operation that encrypts it, so a build that skipped
verification could not decrypt either.

**What replaces the knob is not a setting.** Integrity is a property of the
format, so there is nothing to enable and nothing to get wrong — and, more to the
point, nothing an operator can switch *off* by misreading a configuration
reference. What an operator does need to know is *where* the refusal surfaces —
before the response for anything decided from metadata, as an aborted body once
streaming has begun — and what that costs a client. Section 3.5 states both.

---

## H-6 An object without encryption metadata is served as plaintext — **closed**

**Closed by ADR 0003.** Under an encrypting provider, an object carrying no
proxy metadata — or naming a format this proxy does not read — is refused with
`InvalidObjectState`, HTTP 403, on `GET`, `HEAD` and ranged `GET` alike. The
exit provider serves an object that carries no proxy metadata verbatim, which is
what it is for, and still refuses one whose key material does not authenticate
([SECURITY_ARCHITECTURE.md § 3.2.1](../../SECURITY_ARCHITECTURE.md#321-what-the-exit-provider-means-for-this-threat-model)).
Measured: stripping the format marker, and stripping every proxy key, both
answer 403
([segment_tamper_test.go](../../test/integration/360-degree-variants/segment_tamper_test.go)).

What it was: such an object was served to the client unchanged, whatever the
active provider. Anyone able to write to the backend bucket could substitute an
object by stripping four metadata keys off it, and the proxy would hand the
substituted bytes over as if it had written them.

**The consequence an operator has to plan for** is that a refusal is permanent
and has no repair path in the product. The object is not readable through this
proxy again; it is restored from its source. The 403 is the notification.

---

## H-7 Dead security configuration knobs — **closed**

**Closed by ADR 0013 and ADR 0014.** `s3_security` now carries
`max_clock_skew_seconds` and `max_presign_expiry_seconds`, both read and both
range-checked at startup ([config.go:68-79](../../internal/config/config.go#L68),
[config.go:920-949](../../internal/config/config.go#L920)), and the machinery behind
the deleted keys is gone with them. Verified by grep over the tree: the six key names
appear in no Go file, in no `config/*.yaml`, and in no chart values file.

What it was: six keys under `s3_security` — `enable_rate_limiting`,
`max_requests_per_minute`, `max_failed_attempts`, `unblock_ip_seconds`,
`strict_signature_validation` and `enable_security_logging` — were parsed,
defaulted, range-checked and documented, and read by nothing. No rate limiter, no
block list and no unblock timer existed anywhere in the product. Alongside them,
`s3_backend.use_tls` was read only to assign itself while the scheme of
`target_endpoint` decided the transport, `encryption.integrity_verification`
offered a choice between integrity settings that the format decides, and
`optimizations.streaming_threshold` claimed to choose a cipher that no longer
exists.

**The one piece of machinery that looked like an implementation was worse than
the absence it hid.** It counted authentication failures per client, keyed that
count on the first `X-Forwarded-For` value — an attacker-chosen string — compared
it against a hardcoded `5` rather than the configured value, only ever wrote a
log line, and never expired an entry. Unauthenticated requests therefore grew
proxy memory without bound, under a name that read like brute-force protection.
It is deleted: the type, the map, the accessors, the threshold, the
`getClientIP` helper that produced the attacker-controlled key, and the
`client_ip` and `failed_count` log fields. A security event now logs
`remote_addr` and the raw `X-Forwarded-For` as two separate fields and interprets
neither
([s3auth_robust.go:418-428](../../internal/proxy/middleware/s3auth_robust.go#L418)).

**Per-IP rate limiting was also the wrong tool**, which is why nothing replaced
it: a legitimate client is one authenticated identity that may issue thousands of
requests from one address — Velero bursts from a single pod IP, and anything
behind a NAT looks the same. The controls that do the work here are
authentication and resource limits. Any real limiter arrives with a test that
proves it throttles (ADR 0014).

What this closes is a lie in the configuration, not a hole in the product: there
was never protection where those keys said there was. **The gain is that an
operator can no longer believe otherwise** — and, in the failure-counting case,
that an unauthenticated caller can no longer make the process allocate.

Three decisions taken with this one landed on 2026-09-11; they are
[H-10](#h-10-three-configuration-decisions-are-specified-and-not-built--closed).

---

## H-8 The AES KEK fingerprint is a plain hash of the key — **closed**

**Closed by ADR 0004.** The fingerprint written to every object as
`s3ep-kek-fingerprint` is now
`hex(HKDF-Expand(HKDF-Extract(master key), "s3ep-kek-fingerprint"))`, a
derivation under a label of its own rather than `hex(SHA-256(key))`.

What it was: the published value was a hash of the master key itself. For a
256-bit key from `s3ep-keygen` that was harmless — inverting SHA-256 is not a
thing — but a **low-entropy or published key** could be confirmed offline by
anyone able to read one object, which turned the fingerprint into a verification
oracle for a dictionary attack.

Two changes close it together, and the second is the one that matters:

- The fingerprint is derived under its own label, so it is not a hash of the key
  and confirms nothing about it.
- A key that is not base64 of 32 bytes is refused at startup, and so is one that
  decodes to printable characters only or to fewer than 16 distinct byte values.
  A passphrase can no longer become an AES-256 key, so the dictionary the oracle
  would have been useful against no longer exists.

What remains, and is accepted: the fingerprint still **links deployments** — two
buckets carrying the same value provably share a master key. That is inherent to
selecting the right key by a value the backend can read.

---

## H-9 The replaced format's decrypt path is still in the tree — **closed**

**Closed by ADR 0013, by analogy.** The old whole-object GCM and streaming CTR
readers, the HMAC verifier, the CTR multipart session, the envelope layer and the
whole of `internal/validation/` are deleted; what is left in
`pkg/encryption/dataencryption/` is the segment codec and its readers, and
nothing else. Verified on this tree: `deadcode ./cmd/s3-encryption-proxy`
(`golang.org/x/tools/cmd/deadcode`) reports four unreachable functions, where it
reported 206 before — `Manager.ShortPartBytesHeld`, `Server.Addr` and
`naiveCRC64NVME`, each reached only from tests, and `SealedPart.Streamed`, which
nothing calls at all. Not one of them is a decrypt path, which is what this item
was about.

What it was: nothing reached that code, but all of it compiled.
`Manager.DecryptDataWithMetadata`, the entry point to the algorithm switch that
chose between the old readers, had no production caller — only tests. [Rule 2 of the threat model](../../SECURITY_ARCHITECTURE.md#12-three-rules)
says a control that exists only in configuration or in documentation is worse than no control; the mirror case is an **unauthenticated
decrypt path that exists only in dead code**. It was not a vulnerability, because
no request could reach it, and it would have become one the moment somebody wired
a caller to it — easy to do by accident, because the function names read like the
live ones.

**What it also removed is the last thing that could read an object written by
3.x or 4.0.x.** That is deliberate and is the point of ADR 0017: such an object
is refused, not read ([SECURITY_ARCHITECTURE.md § 1.2](../../SECURITY_ARCHITECTURE.md#12-three-rules), rule 3).

