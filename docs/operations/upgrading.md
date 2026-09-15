# Upgrading from 3.x or 4.x to 5.x

Read this before you upgrade. **Objects written by an earlier release cannot be
read by 5.x** — copy the data out with the old version first — and a
configuration file written for 4.x will stop the proxy at startup until it is
brought forward. Every refusal below names the key it is about.

## What changed

The breaks, all deliberate ([ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md)):

- **Objects written by an earlier release cannot be read.** They carry a
  different format id, so every `GET`, `HEAD` and ranged `GET` answers `403
  InvalidObjectState` rather than handing out bytes the proxy cannot
  authenticate. Copy the data out with the old version before upgrading.
- **`type: "none"` is gone; that provider is now `exit`.** A file that still
  says `none` is refused at startup by name. It is not a rename: the exit
  provider passes writes through on *every* write path, not only on a
  single-request `PUT`, and it keeps decrypting objects this proxy encrypted
  earlier — so the `aes` provider holding their key has to stay listed beside it
  ([the exit provider](../../README.md#the-exit-provider)).
- **`type: "rsa"` is gone, with its `public_key_pem` and `private_key_pem`.**
  There is one local key provider, and any other type is refused as unsupported
  whether or not it is the one that writes
  ([ADR 0004](../adr/0004-one-local-key-provider.md)).
- **`aes_key` is now base64 of exactly 32 random bytes.** 4.x used the string's
  own bytes when it did not decode to 32, so a raw 32-character passphrase was a
  working key; it is refused at startup now, as is a decoded key that is all
  printable or carries fewer than 16 distinct byte values. Generate a new one —
  the objects written under the old one are unreadable to this release anyway.
- **Configuration keys that no code read are gone, and a key the proxy does not
  define now refuses the start instead of being ignored.** That second half is
  what makes the first one safe: a removed key used to be dropped in silence, so
  a setting an operator believed was in force was not. Removed:
  `encryption.integrity_verification` and the four HMAC modes behind it,
  `optimizations.streaming_threshold`, `streaming_buffer_size`,
  `enable_adaptive_buffering`, `clean_aws_signature_v4_chunked` and
  `clean_http_transfer_chunked`, `s3_backend.use_tls`, and every `s3_security`
  key except `max_clock_skew_seconds`.
  `optimizations.multipart_session_max_age` is gone too, refused by a message of
  its own because the replacement `multipart_session_idle_timeout` counts from a
  different point. Integrity is no longer a setting: it is the storage format,
  on every read
  ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).
  The legacy top-level backend block — `target_endpoint`, `region`,
  `access_key_id`, `secret_key`, `use_tls`, `skip_ssl_verification` — is no
  longer migrated into the backend block, and it is now named in the refusal
  rather than producing only `s3_backends[0].target_endpoint is required`.
  **Go through your configuration before upgrading:** a leftover key, or a
  misspelled one, stops the proxy at startup, and the error names it.
- **`s3_backend` is now the list `s3_backends`.** The old key is refused at
  startup by a message of its own telling you to move the block under a single
  `- ` entry. The entry's fields — `target_endpoint`, `region`, `access_key_id`,
  `secret_key`, `insecure_skip_verify` — and their checks are unchanged, so a
  file works again as soon as the block is indented; startup messages about the
  backend now name `s3_backends[0]`. **This release reads exactly one entry and
  refuses a second by name**: the list is the shape, not yet the feature. It is
  here because backends are symmetric — a deployment that keeps several in sync
  names them all and none of them is *the* backend — and because turning a
  mapping into a list in a later release would refuse every configuration
  written for this one, which a major release is the place to pay for
  ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11).
- **The Helm chart installs one instance and refuses a second.** `replicaCount`
  above 1 and `autoscaling.enabled: true` both fail the render with a message
  naming the reason, and the shipped `values-production.yaml` — three replicas
  and autoscaling to twenty until this release — now installs one, with
  autoscaling and the pod disruption budget off. A deployment running more than
  one pod has to come down to one before it upgrades; why it never worked is
  under [Kubernetes with Helm](deployment.md#kubernetes-with-helm).
- **`optimizations.streaming_segment_size` is now
  `optimizations.multipart_part_size`.** The old name is refused at startup by a
  message of its own that names the replacement, rather than as an unknown key:
  the two are the same setting. The value, the 12 MiB default and the checks — a
  5 MiB minimum, a 5 GiB maximum, a whole multiple of 64 KiB — are unchanged, so
  a file works again as soon as the key is renamed
  ([ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)).
- **A provider's `config:` block is strict too.** It used to swallow whatever it
  was given: each provider read the one key it wanted and dropped the rest, so a
  key written one level too deep — `metadata_key_prefix` inside a provider is the
  case that actually happened — did nothing and said nothing. Every type now
  declares what it reads: `aes` reads `aes_key`, `exit` reads nothing at all, and
  any other key refuses the start naming it and its provider.
- **The license reaches the proxy through `S3EP_LICENSE_TOKEN` and `license_file`,
  and nothing else.** `S3EP_LICENSE` and `S3_ENCRYPTION_PROXY_LICENSE` are no
  longer read, and neither is the list of well-known paths that used to be
  searched when `license_file` was not written — `license.jwt`,
  `build/license.jwt`, `/etc/s3ep/license.jwt`, `/opt/s3ep/license.jwt`,
  `/app/license.jwt` and `./config/license.jwt`. A deployment on either other
  variable, or on a path other than the one `license_file` names, starts
  unlicensed and is refused unless its active provider is `exit`. A token found
  somewhere the operator did not name is a token they cannot rotate
  ([ADR 0016](../adr/0016-the-license-is-a-startup-gate.md) D6). The shipped
  image and the Helm chart are unaffected: both write `license_file`.
- **New refusals at startup, each naming the key.** A `target_endpoint` with no
  scheme, or `http://` under any provider — the exit provider included; an
  `encryption.metadata_key_prefix` shorter than four characters, not starting
  with a letter or digit, or not ending in `-`; an
  `optimizations.multipart_part_size` that is not a multiple of 64 KiB; a
  `max_clock_skew_seconds` or a `max_presign_expiry_seconds` of `0`; a
  `read_header_timeout` or `idle_timeout` of `0`.
- **`max_clock_skew_seconds` now governs both authentication forms.** It used to
  reach pre-signed URLs only, while the `Authorization`-header path — the one
  every AWS SDK client takes — compared against a fixed 900 seconds. If your
  configuration narrows the window, it now narrows for every request. **A client
  whose clock is off by more than the configured window starts being refused**,
  and every shipped example sets 300 seconds where the header path used to allow
  900. Check client clocks before upgrading.
- **Pre-signed URLs are bounded to one hour by default**
  (`s3_security.max_presign_expiry_seconds`), not to the S3 maximum of seven
  days. A client that mints longer URLs needs the setting raised.

