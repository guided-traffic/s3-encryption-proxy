# 036 — `SelectObjectContent` is refused with `SignatureDoesNotMatch`

Found 2026-09-13, by making a test honest rather than by looking for it.
`TestPassthroughOperations_SelectObjectContent` drove the verb and then swallowed
whatever came back in a `t.Logf` — it could not fail, and it had been passing over
a defect for as long as it existed.

## What happens

`SelectObjectContent` through the proxy answers **`403 SignatureDoesNotMatch`**.
The decided answer is `501 NotImplemented` (ADR 0007 D8): the proxy refuses the
verb itself, because it would have to run a query over plaintext the backend does
not hold. The handler that answers it exists and is routed; the request never
reaches it, because authentication refuses first.

## It is this proxy's defect, and the oracle says so

The same call, from the same process, with the same aws-sdk-go-v2 build:

```
minio direct : 400 InvalidTextEncoding: UTF-8 encoding is required.
via the proxy: 403 SignatureDoesNotMatch
```

MinIO verified the signature and got as far as complaining about the payload. The
proxy could not verify the same signature. A client is not at fault for a request
the backend accepts.

## What has been ruled out

- **Not a missing signed header.** That path returns
  `signed header %s not found in request` from `buildCanonicalHeaders`, and the
  security event logged `details="signature mismatch"` — the canonical request was
  built and the signatures were compared, and they differed.
- **Not the empty query parameter.** `?select` renders as `select=` in the
  canonical query, which is what SigV4 prescribes, and `?acl` — the same shape —
  authenticates today.

## What is not known

Which element of the canonical request differs. The candidates worth taking in
order: the payload hash the SDK signs for this verb against what the proxy reads
from `x-amz-content-sha256`; whether `net/http` alters a header this verb signs
and `?acl` does not; and the exact canonical request each side built, which is
worth logging once behind the debug level rather than guessed at a third time.

## Why it matters beyond this verb

The verb itself is refused either way, so no client loses a feature. What the
defect says is that **this proxy rejects a signature a backend accepts**, on a
request shape nothing else in the suite covers. Whatever causes it may be reachable
from another verb that is not refused, and `SignatureDoesNotMatch` is the answer a
client can do least with — it reads as "your credentials are wrong".

## Done when

- [ ] `SelectObjectContent` through the proxy answers `501 NotImplemented`.
- [ ] The cause is named in the fix, and if it is a canonical-request element, a
      test covers that element rather than this verb.
- [ ] `TestPassthroughOperations_SelectObjectContent` is green, and this file is
      deleted.
