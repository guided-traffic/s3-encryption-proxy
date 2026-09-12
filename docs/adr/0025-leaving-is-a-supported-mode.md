# ADR 0025: Leaving is a supported mode

## Status

**Accepted.** Date: 2026-09-10.

**Implemented on the 5.0.0 branch the same day.** The provider type is `exit`; `none` is refused
by name with a message that points at it. All three write paths store plaintext, every read path
decides per object — whole-object `GET`, ranged `GET` and `HEAD`, verified 2026-09-12 — and the
licence gate lets the exit provider start without a licence because it only ever looked at the
active provider.

This supersedes D10 of [ADR 0004](0004-one-local-key-provider.md), which kept a pass-through
provider "for testing and end-of-life only". The end-of-life half is now the whole point and it is
specified here; the testing half survives as a consequence rather than a purpose, because in a
bucket that holds nothing this proxy encrypted, the exit provider behaves exactly as pure
pass-through did.

## Context

A product that encrypts data at rest owes its operator a way out. Without one, the encryption is
not a feature but a hostage: the data is readable only for as long as the licence is valid, the
software runs and the operator keeps paying. That is true of every envelope-encryption proxy and it
is the objection a careful buyer raises first.

The tree had something that looked like an answer and was not. A provider of type `none` existed,
needed no licence, and passed writes through. But it also passed **reads** through: under `none`
the read path returned whatever the backend held, without looking at the object's metadata. So an
operator who switched to it in order to stop encrypting immediately lost the ability to read
everything encrypted before the switch — the proxy handed back raw ciphertext. The one mode that
was supposed to be the way out was the mode in which the old data became unreadable.

Two further defects made it worse. The pass-through was honoured only on the single-request write
path: an object above one part, and every client-driven multipart upload, was still encrypted, with
its data key wrapped by a pass-through key encryptor that returned it unchanged — the key stored in
the clear beside the object. A bucket inspected at rest then looked encrypted while the key sat
next to it. And the read path took the pass-through unwrap whenever *object metadata* named the
pass-through fingerprint, whatever the configured provider was, which handed a hostile backend a
forgery oracle: choose a data key, store it verbatim, seal any plaintext under it, and every
segment authenticates ([ADR 0001](0001-the-backend-is-hostile.md)).

The name was the smallest of the problems and the clearest signal: `none` described a provider that
did something.

## Decision

**D1.** The provider type is **`exit`**. It is the supported way to stop using the product without
losing access to what it already encrypted. It is not a testing aid, not a development mode, and
not a way to run the proxy as a plain pass-through in production.

**D2.** **The exit provider requires no licence.** Getting data out is exactly the situation in
which a licence cannot be assumed to be valid, so making it a condition would defeat the purpose.
The licence gate examines the active provider only, so a configuration with `exit` active starts
without one even while an encrypting provider stays registered.

**D3.** **On write the exit provider stores what the client sent.** No data key is created, no
wrap happens, no proxy metadata is written, and this holds on every write path: the single request,
the internal multipart producer and the client-driven multipart upload. A partial pass-through —
plaintext for small objects and ciphertext for large ones — is the defect this decision exists to
remove, and it is worse than either alternative because a bucket then looks protected while the key
sits beside the object.

**D4.** **On read the exit provider still decrypts.** An object carrying the proxy's metadata is
opened exactly as under an encrypting provider: the object's own key fingerprint selects the
provider that wrapped its data key. That provider must therefore stay configured alongside the exit
provider. If the operator removes it, those objects become unreadable — which is the same statement
as "do not delete the key", said in configuration.

**D5.** **The decision is per object, not per provider.** Under the exit provider a bucket
legitimately holds both: what was encrypted before the switch and what has been written plainly
since. An object carrying the proxy's metadata is decrypted; one that does not is served verbatim.
Under an encrypting provider an object the proxy did not write is still refused
([ADR 0001](0001-the-backend-is-hostile.md)) — the exit provider is the only mode in which a
foreign object is a normal thing to find.

**D6.** **The exit provider holds no key material.** It satisfies the key-encryptor interface so
that it can be selected like any other provider, and both of its key operations return an error.
Reaching either is a bug: a write path that failed to pass through, or a fingerprint accepted that
names no real key. This is also what closes the forgery of D7.

**D7.** **No fingerprint is special-cased on the read path.** A wrapped key is unwrapped by the
provider its fingerprint names, or the read fails. Because the exit provider refuses to unwrap, a
backend that labels an object with the exit fingerprint gets a refusal rather than a data key of
its own choosing, whatever the active provider is.

**D8.** **A listing reports the stored size verbatim under the exit provider.** Inverting the
size arithmetic would be exact for the objects encrypted before the switch and would under-report
some plain ones, because a plain object's size can coincide with a stored size the arithmetic
accepts. Over-reporting costs a client a re-transfer; under-reporting can make a synchronising
client believe the remote copy is short and write over it. The safe direction to be wrong in is
the one that costs bandwidth.

**D9.** **`type: "none"` is refused by name**, with a message that names `exit` and says to keep
the provider holding the old key configured alongside it. No silent alias and no deprecation
period ([ADR 0017](0017-stored-data-compatibility-is-not-owed.md)).

**D10.** **The proxy says so at every start.** An active exit provider logs that new objects are
stored unencrypted and that previously encrypted objects are still readable while their provider
stays configured. It is a warning, not an error: the operator asked for this.

## Consequences

An operator can leave. The migration is: register the exit provider, make it active, keep the
`aes` provider that holds the key, and let the data age out — or copy it through any S3 client,
which now reads plaintext and writes plaintext. Nothing has to be decrypted in a batch, no tool
has to be written, and no licence has to be renewed to do it.

A ranged read costs one extra request under the exit provider. The stored window for an encrypted
object is not the plaintext range, so the proxy must know which kind of object it is before it
asks for a byte range, and that answer costs a `HEAD`. Under an encrypting provider nothing
changes and an explicit range still costs one backend request
([ADR 0003](0003-objects-are-an-authenticated-segment-chain.md) D9). Exit is a migration state
rather than a steady one, which is what makes the extra request acceptable.

Under the exit provider new objects have no protection from the backend at all. That is the
operator's declared intent and it is stated at every start, but it means the threat model of
[ADR 0001](0001-the-backend-is-hostile.md) applies only to the objects written earlier. The read
path still refuses an object whose key material does not authenticate, so the guarantee that
survives is the one about the old data, not about the new.

The pass-through key encryptor is gone as a concept. Nothing in the product now returns a data key
unchanged, which removes a class of defect rather than an instance of one: there is no code path
left that can be persuaded to treat an attacker-supplied value as a key.

## Alternatives Considered

**Keep `none` as it was and document the trap.** Rejected. The documentation would have had to say
that the mode named for leaving is the mode in which the old data stops being readable. A control
that behaves opposite to its name is the defect this project refuses everywhere else.

**A batch decrypt tool instead of a provider.** Rejected as the primary answer. It is more code,
it needs its own credentials and its own failure handling, it cannot run while the proxy serves,
and it forces the operator to move every byte twice. The exit provider costs an operator one
configuration change and lets ordinary S3 clients do the copying — and a tool can still be added
later for someone who wants the bucket converted in place.

**Make the exit provider refuse objects it cannot open.** Rejected. Under exit a bucket
legitimately holds foreign plaintext — content written straight to the backend, or by another tool
— and refusing it would make the exit mode useless for exactly the mixed bucket it exists to drain.
An object that *is* ours and cannot be opened is still refused: that is a missing key, not a
foreign object.

**Invert the size arithmetic in listings under exit.** Rejected, see D8.

## Residual risks

An operator who removes the `aes` provider after switching to exit loses the old objects. Nothing
prevents it, because nothing can distinguish it from a deliberate decommissioning. The startup line
says the provider must stay; the configuration does not enforce it, and enforcing it would mean
refusing to start over data that may no longer exist.

The exit provider cannot tell a client that a given object is plaintext or ciphertext. A client
that needs to know has to read the object metadata itself, and the proxy strips its own namespace
from every response ([ADR 0009](0009-the-metadata-prefix-is-the-proxys-namespace.md)) — the
whole-object pass-through included, which is where it was not true until 2026-09-12. This has not
been raised as a requirement; it is recorded because a migration tool might want it.

The extra `HEAD` on a ranged read under exit has not been measured. It is one request against a
backend that already answers the range request, so the cost is a round trip rather than a transfer,
but the claim is reasoned rather than recorded.

## References

- [ADR 0001](0001-the-backend-is-hostile.md) — why a fingerprint from object metadata may not
  select a no-op unwrap.
- [ADR 0004](0004-one-local-key-provider.md) — the local key provider whose D10 this supersedes.
- [ADR 0016](0016-the-license-is-a-startup-gate.md) — the gate the exit provider is exempt from.
- [ADR 0017](0017-stored-data-compatibility-is-not-owed.md) — why `none` is refused rather than
  aliased.
