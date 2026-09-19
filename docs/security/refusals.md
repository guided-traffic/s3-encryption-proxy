# Refusals: where the proxy says no rather than pretending

Rule 2 of [the threat model](threat-model.md#three-rules) applied to a handler:
an operation that answers `200` for work it did not do is worse than one that
refuses. This page is the list of operations that refuse, and of the three that
used to pretend.

The following now return an explicit refusal —
`NotImplemented` ([errors.go:98](../../internal/proxy/response/errors.go#L98)) unless
noted — instead of a misleading success:

- `SelectObjectContent`.
- `GET /bucket/key?attributes`, which used to return the object **bytes** where
  an XML document was expected ([handler.go:120-125](../../internal/proxy/handlers/object/handler.go#L120)).
- `UploadPartCopy` answers `422 NotSupportedWithEncryption`
  ([copy.go:35-44](../../internal/proxy/handlers/multipart/copy.go#L35),
  [errors.go:112-121](../../internal/proxy/response/errors.go#L112)) — a server-side
  copy cannot be re-encrypted at the proxy. It was previously **unreachable**
  (the route was shadowed and its header matcher compared the literal string
  `{source}`), so such a request silently stored a 0-byte part; the route now
  matches and the honest error is returned
  ([router.go:113-117](../../internal/proxy/router.go#L113)).
- Client-issued `CopyObject` (`PUT` with `x-amz-copy-source`) answers the same
  `422 NotSupportedWithEncryption`
  ([operations.go:337-351](../../internal/proxy/handlers/object/operations.go#L337)).
  A server-side copy would move ciphertext without re-encrypting it, so the
  proxy neither performs one nor keeps the ability to: `CopyObject` is no longer
  on the backend interface at all
  ([privilege footprint](tenancy-and-privilege.md#what-the-proxy-can-do-to-the-backend-bucket)).
- Object ACL, `GET` and `PUT`. `?tagging`, `?retention` and `?legal-hold` left
  this list with ADR 0007 D4 and now carry their document to the backend; the
  refusal itself had replaced something worse — the old legal-hold handler read
  the body, discarded it and **always set the hold ON**, so a client asking to
  release a hold applied one instead.
- Any bucket sub-resource without a route. Previously such a request fell through
  to the base operation for its HTTP method, which is how
  `DELETE /bucket?encryption` deleted the bucket
  ([handler.go:99-133](../../internal/proxy/handlers/bucket/handler.go#L99)).

**The handler that used to pretend, closed 2026-09-11.** `ListParts` answered
`200` with a fabricated, always-empty `ListPartsResult` and never asked anything,
so a client could not use it to discover what a multipart upload held — the
failure mode under rule 2 that this section is about. It is answered from the
part table the session keeps
([list.go](../../internal/proxy/handlers/multipart/list.go),
[segmented_session.go](../../internal/orchestration/segmented_session.go)): the
plaintext size and the entity tag per part, the held last part included, and
`404 NoSuchUpload` for an upload id the proxy has no session for.

**The guard that used to fail open, closed 2026-09-11.**
`x-amz-expected-bucket-owner` is the client's defence against a bucket name it no
longer owns — the original bucket deleted, the name re-registered by another
account, the client still writing to it. S3 answers `403 AccessDenied` when the
bucket belongs to someone else. Exactly one verb of this proxy honoured it
(`DeleteBucket`); every other one read the header, dropped it and answered
success, so a client that had set the guard on `PUT`, `DeleteObject` or
`DeleteObjects` was not guarded and had no way to tell. It is now carried on every
backend call the proxy makes, from one reader
([bucketowner.go](../../internal/proxy/request/bucketowner.go)), with a source-level test
that fails on a call site which omits it
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D14).

This is rule 2 applied to a security control: a dropped preference is a missing
feature, a dropped guard is a false assurance, and the second is worse than
never offering it. Honouring it on some verbs would have been worse still — a
client tests the guard on one verb and trusts it on all of them.

`x-amz-bypass-governance-retention` and `x-amz-mfa` are still dropped on the
delete paths. They are a capability gap rather than a false assurance: without
them the backend refuses the delete, so they fail closed.

## What this does not cover

- **A refusal is a control against a client mistake, not against the backend.**
  Every entry here is about what this proxy answers. Nothing on this page
  constrains what the backend does with an object it already holds.
- **Two headers are still dropped on the delete paths**, named above:
  `x-amz-bypass-governance-retention` and `x-amz-mfa`. They fail closed, so they
  are a capability gap rather than a false assurance — but a client that needs
  either cannot get it through this proxy.
- **Most header families are forwarded rather than refused**, and what that
  hands the backend is
  [what the backend learns anyway](stored-objects.md#what-the-backend-learns-anyway).
