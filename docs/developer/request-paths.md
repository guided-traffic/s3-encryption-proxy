# Request paths

What happens between the listener and the backend, per verb. Handlers live in
`internal/proxy/handlers/`; everything they do to an object goes through
`internal/orchestration.Manager` and nothing below it.

## PUT

```
PUT /{bucket}/{key}
  ├─ x-amz-copy-source present?  → refused, 422 NotSupportedWithEncryption
  │                                 (the proxy cannot re-encrypt inside the backend)
  ├─ plaintextLen = DecodedContentLength(r)
  │     X-Amz-Decoded-Content-Length when present, else Content-Length, else -1
  │
  ├─ plaintextLen < 0  or  > streaming_segment_size
  │     → the internal multipart producer
  └─ otherwise
        → one PutObject, sealing as the backend reads
```

**Route on the plaintext length, never on the wire length.** The wire length of
an aws-chunked upload includes the chunk framing and the trailer, so routing on
it would make the decision depend on how the client framed the request rather
than on how big the object is.

There is no threshold to tune and no second cipher to choose. The only thing the
size decides is whether the object fits in one backend request.

**A declared length is enforced without an explicit check.** The codec is given
the plaintext length up front and the backend is promised the ciphertext length
that follows from it, so a body that ends early cannot fill it: the upload fails
and nothing is stored. Verified over the wire on both write paths.

## GET

```
GET /{bucket}/{key}
  ├─ Range header the proxy can act on?  → the ranged path below
  ├─ GetObject from the backend
  ├─ no proxy metadata, or a foreign format id
  │     → 403 InvalidObjectState, under an encrypting provider
  │       (the none provider passes everything through)
  ├─ the wrapped key fails its tag
  │     → 403 InvalidObjectState
  └─ stream: open segment by segment, release each after it verifies
        a fault here aborts the body — see storage-format.md
```

The response is composed from an allowlist, never proxied. The backend's
`x-amz-checksum-*` describe stored ciphertext, its `Content-Length` describes
stored bytes, and its metadata carries the proxy's own keys — none of that may
reach a client. `Handler.cleanMetadata` drops every key under the configured
prefix.

## Ranged GET

The window is planned from the requested plaintext range, then exactly that
ciphertext window is fetched. `Content-Range` describes **plaintext** offsets and
the plaintext total, so a client never has to know the object is stored
encrypted.

An explicit `bytes=a-b` costs one backend request: the window is planned
optimistically, the backend clamps it, and the object's real length comes back in
the same answer's `Content-Range`. A suffix (`bytes=-500`) or open-ended
(`bytes=100-`) range is relative to the end of the object, so its length is
needed first and it costs a `HEAD` ahead of the `GET`.

A Range header the proxy cannot parse, and a multi-range header, are **ignored**
— the whole object is served — because that is what AWS does. A range past the
end is `416` with `bytes */plaintext-size`, composed by the proxy rather than
relayed.

## HEAD

Answered from the backend's own `HEAD`. The plaintext size is arithmetic on the
stored size, so no second request is needed. The same refusal rules as `GET`
apply, including when the backend reports no length — a `HEAD` that confirmed an
object `GET` would refuse was a defect, and it is pinned.

## What is refused rather than pretended

A verb or sub-resource the proxy does not implement answers `NotImplemented`
rather than being forwarded or silently ignored
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md)). Bucket sub-resources are
routed from an allowlist and anything not on it is refused. That is deliberate:
an operation that appears to succeed and did nothing is worse than one that says
no.
