# rclone

rclone has an end-to-end suite in [`test/e2e/rclone/`](../../../test/e2e/rclone/), run
against a pinned rclone release on the demo stack over both proxy endpoints:

```bash
make e2e-rclone-up     # install the pinned rclone + start the demo stack
make test-e2e-rclone   # R1-R7, both endpoints, incl. encryption-at-rest checks
make e2e-rclone-down
```

The pinned version lives in
[`test/e2e/rclone/versions.env`](../../../test/e2e/rclone/versions.env) and is tracked
by Renovate as the group "client e2e". Every run writes
`test-results/e2e-rclone-verdicts.md`: one row per case per endpoint, in
rclone's own words.

**The remote to configure**, and it is the one the suite drives:

```ini
[s3ep]
type = s3
provider = Minio
env_auth = false
access_key_id = <your s3_clients entry>
secret_access_key = <its secret>
endpoint = https://proxy.example.com
region = us-east-1
force_path_style = true

# Required today. Without it rclone rebuilds S3's multipart ETag from the MD5s
# of its own plaintext parts and compares the whole string against what the
# proxy answered. The parts this proxy stores are ciphertext, so the two can
# never agree — and no value the proxy could answer would make them, because its
# entity tag is a change token and not a content digest by decision
# (see "Entity tags" in ../integrity.md). The upload is verified regardless:
# rclone sends a Content-MD5 with every part and this proxy checks each one
# against the decoded plaintext before a byte reaches the backend.
use_multipart_etag = false
```

`provider = Other` has the same effect, because that entry already defaults the
comparison off — but `Minio` plus the explicit line says what is going on, and
it keeps the rest of that provider's behaviour.

Nothing else is needed: single-request uploads, downloads, `check`, `sync`,
`hashsum` and the listings all work with rclone's defaults.

## Configuration notes for a real rclone deployment

- Point the remote at the proxy over **HTTPS** with `force_path_style = true`.
  rclone is built on the AWS SDK for Go and, like it, emits its checksum-trailer
  request framing over TLS only.
- **rclone verifies both directions against the entity tag, and this proxy's
  entity tag is not a digest of your file** — it says so in its shape, which is
  what makes rclone stop comparing it ([Entity tags](../integrity.md#entity-tags)). Before the
  marker, an object written by a single request was reported `corrupted on
  transfer: md5 hashes differ` on upload and download alike and deleted by
  rclone; `rclone check` called an intact object different and
  `rclone sync --checksum` re-uploaded everything on every run. None of that
  needs a flag any more.
- **`use_multipart_etag = false` is the one line this product asks for**, and
  the block above says why. It is a documented limit
  ([ADR 0032](../../adr/0032-the-entity-tag-is-a-change-token-never-a-content-digest.md)
  D9), not a defect waiting for a fix: the comparison it switches off cannot be
  satisfied by any entity tag an encrypting proxy could answer. It goes away the
  day rclone carries a provider entry for this endpoint, which one provider
  already carries for the same reason.
- On a multipart object rclone stores its own plaintext MD5 as
  `X-Amz-Meta-Md5chksum`, the proxy preserves it, and `rclone hashsum md5`,
  `rclone check` and `rclone lsjson --hash` then all report the plaintext
  digest. It writes no such annotation for a single-request upload, so for those
  objects `rclone hashsum md5` reports **no hash at all** rather than a wrong
  one. That value is written by rclone, in the clear, beside the ciphertext:
  useful, and not something this proxy vouches for.

