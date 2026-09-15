# s3cmd

s3cmd has an end-to-end suite in [`test/e2e/s3cmd/`](../../../test/e2e/s3cmd/), run the
same way:

```bash
make e2e-s3cmd-up      # install the pinned s3cmd + start the demo stack
make test-e2e-s3cmd    # S1-S7, both endpoints, incl. encryption-at-rest checks
make e2e-s3cmd-down
```

The pinned version lives in
[`test/e2e/s3cmd/versions.env`](../../../test/e2e/s3cmd/versions.env), same Renovate
group, and each run writes `test-results/e2e-s3cmd-verdicts.md`.

## Configuration notes for a real s3cmd deployment

- Path-style addressing is what this proxy serves, so set `host_bucket` to the
  same value as `host_base` — s3cmd switches to virtual-host style if and only
  if `host_bucket` carries the literal `%(bucket)s`. Set `bucket_location` to
  your region rather than leaving it at its `US` default, which makes s3cmd
  issue a `GET ?location` before every signed request. Point `ca_certs_file` at
  your CA rather than turning verification off.
- **s3cmd compares the entity tag of every PUT — and of every uploaded part —
  with the MD5 of the bytes it sent**, and has no option that switches that check
  off. The marker of [Entity tags](../integrity.md#entity-tags) is what makes it stop: a tag
  carrying a hyphen is one s3cmd does not treat as a digest, which is why the
  marker covers a part's answer and not only the object's. Before it, a `put`
  warned `MD5 Sums don't match!` and exited 2, a multipart `put` was refused on
  its **first part** and left an upload open, and `sync` re-uploaded every
  unchanged file on every run.
- **What that costs, and it is worth knowing:** s3cmd sends no `Content-MD5` for
  an object body, so once it stops comparing the entity tag there is no
  end-to-end digest of an s3cmd upload anywhere. Over HTTPS the TLS record MAC
  covers the wire; over the plain listener nothing does. Use the TLS endpoint
  with s3cmd.
- `s3cmd del --recursive` and `s3cmd multipart` are refused (`501` and `405`):
  s3cmd addresses a bucket with a trailing slash and this proxy does not route
  `POST /bucket/?delete` or `GET /bucket/?uploads`. Delete objects by their full
  key, and clear an abandoned upload from the backend.
- On read s3cmd prefers the plaintext MD5 in its own `x-amz-meta-s3cmd-attrs`,
  which the proxy preserves, so `get` verifies and both `info` and
  `ls --list-md5` report the same digest — the latter falls back to that
  annotation exactly because the entity tag now carries a hyphen. That value is
  written by s3cmd, in the clear, beside the ciphertext: it is the client's own
  bookkeeping, not something this proxy vouches for.


