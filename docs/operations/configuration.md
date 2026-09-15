# Configuration guide

**The complete key reference — every key the proxy reads, with its default — is
in [README.md](../../README.md#configuration).** It is not repeated here, so a
default has one home and cannot drift.

This page carries what does not fit beside a key: the rules behind the settings
that bite, the `${VAR}` mechanism, the configuration the shipped container image
starts from, and the example files. Where a value comes from *inside the code* is
[docs/developer/configuration.md](../developer/configuration.md).

> A key the proxy does not define **refuses the start**, and the error names it
> ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).
> There is no key that is ignored, and no environment variable that overrides
> one. Coming from 3.x or 4.x, read [upgrading.md](upgrading.md) first.

## The settings that need more than a line


### Body decoding carries no configuration

aws-chunked framing is always
decoded — the only thing switching it off could do is store chunk framing as
object content — and nothing else reaches a handler still framed, because
`net/http` strips `Transfer-Encoding` before the request is dispatched.

### `multipart_part_size` must be a multiple of 64 KiB

It is
measured in plaintext bytes, and a part that does not cover whole segments
cannot sit in the middle of the chain. The default 12582912 (12 MiB) is a
multiple; a value like `6000000` is not and the proxy refuses to start with
`optimizations.multipart_part_size: must be a multiple of 65536 bytes
(64 KiB)`, rather than accepting it and failing every upload larger than one
part ([ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)).

### An upload that goes quiet is ended, not just forgotten

A client-driven
multipart upload that receives no part for `multipart_session_idle_timeout`
seconds is aborted at the backend and then dropped from the proxy; a
`CompleteMultipartUpload` afterwards answers `404 NoSuchUpload`. The clock
measures inactivity rather than the length of the upload, so an upload is never
ended for having many parts, for taking hours over them, or for sending one
part slowly: the clock moves with every byte that arrives, inside a part as
well as between two
([ADR 0028](../adr/0028-an-abandoned-upload-is-ended-not-forgotten.md)).

So size this against the longest *pause* your client may leave between the
bytes it sends — a stalled connection, a client waiting on something else — and
not against how long a part or an upload takes. Each ended upload is logged at
`info` with its upload id, bucket, key and the idle time measured, so the log
says when this is what happened.

`optimizations.multipart_session_max_age` used to name this and measured from
the start of the upload instead. It no longer exists: a configuration carrying
it refuses the start with a message naming the replacement, because the same
number means something else under the new rule.

**A graceful shutdown ends them too.** On `SIGTERM` the proxy answers `503` on
`/readyz` so a readiness probe takes it out of rotation — `/livez` stays `200`
throughout, because the only reaction to a failing liveness probe is a restart
and a restart is what would strand these uploads
([ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md))
— answers every new S3
request `503 ServiceUnavailable` with `Retry-After` **without closing the
listener** — so a client that arrives before the rotation change has propagated
retries against another replica instead of meeting a refused connection — lets
the transfers already running finish, and then aborts every multipart upload it
is still holding, and then exits — it does not sit out the rest of the budget,
because by then a replacement instance has the traffic — because nothing can finish those once
the process exits: the data key and the part layout live in that process and
nowhere else. All four steps share the one `shutdown_timeout` budget
([ADR 0029](../adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)).

**What no proxy can cover is a proxy that is killed.** A crash, an OOM kill or
a `SIGKILL` leaves no shutdown period, the session dies with the process, and
nothing is left to abort the upload. Set a bucket lifecycle rule with
`AbortIncompleteMultipartUpload` for those; it is the only thing that catches
them, and it is worth having regardless.

## Environment Variable References

Configuration values can reference environment variables using the `${VAR_NAME}` syntax. This avoids storing secrets directly in config files.

**Supported fields:**
- `s3_backends[].target_endpoint`, `s3_backends[].region`
- `s3_backends[].access_key_id`, `s3_backends[].secret_key`
- `s3_clients[].access_key_id`, `s3_clients[].secret_key`
- All string values in `encryption.providers[].config` — for the `aes` provider that is `aes_key`

The list is deliberate rather than "every string": a value where a `$` is
legitimate must not be rewritten. **There is no other environment mechanism.**
A configuration key is what the file says it is — no variable overrides one,
which is why a control an operator writes down stays in force.

**Behavior:**
- Only `${VAR}` syntax is expanded (bare `$VAR` is **not** expanded — safe for passwords containing `$`)
- If a referenced variable is not set or empty, the proxy **refuses to start** with a clear error message
- Partial expansion works: `"prefix-${VAR}-suffix"`
- Values without `${...}` are used as-is (no change to existing configs)

**Example configuration:**
```yaml
s3_backends:
  - access_key_id: "${S3_ACCESS_KEY_ID}"
    secret_key: "${S3_SECRET_KEY}"

s3_clients:
  - type: "static"
    access_key_id: "${CLIENT_ACCESS_KEY}"
    secret_key: "${CLIENT_SECRET_KEY}"

encryption:
  providers:
    - alias: "aes-envelope"
      type: "aes"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

**Setting the variables:**
```bash
# S3 Backend credentials
export S3_ACCESS_KEY_ID="your-access-key"
export S3_SECRET_KEY="your-secret-key"

# AES key. s3ep-keygen prints a banner around the key, so take the key line only.
export S3EP_AES_KEY="$(./build/s3ep-keygen | sed -n 2p)"
```

## The container's own configuration

The image starts from **`/app/config/default.yaml`** — it is in this repository
as [`config/default.yaml`](../../config/default.yaml) — and that file takes every
value it needs from an environment variable. It is what makes a plain
`docker run` work without mounting anything.

| Variable | Configuration key | What it is |
|---|---|---|
| `S3EP_BACKEND_ENDPOINT` | `s3_backends[0].target_endpoint` | The S3 backend, **with a scheme**. `http://` is refused under every provider, the exit provider included |
| `S3EP_BACKEND_REGION` | `s3_backends[0].region` | The backend's region |
| `S3EP_BACKEND_ACCESS_KEY_ID` | `s3_backends[0].access_key_id` | The credential the proxy uses against the backend |
| `S3EP_BACKEND_SECRET_KEY` | `s3_backends[0].secret_key` | — |
| `S3EP_CLIENT_ACCESS_KEY_ID` | `s3_clients[0].access_key_id` | The credential a client uses against the proxy. Minimum 8 characters |
| `S3EP_CLIENT_SECRET_KEY` | `s3_clients[0].secret_key` | Minimum 16 characters |
| `S3EP_AES_KEY` | `encryption.providers[0].config.aes_key` | The key encryption key: base64 of exactly 32 random bytes |

`S3EP_LICENSE_TOKEN` is read directly rather than through the configuration, and
an encrypting provider needs it.

**All seven are mandatory, and that is the point.** A `${VAR}` that is unset or
empty is a named startup error, so there is no half-configured start, no empty
credential and no empty key. The shipped file names an **`aes`** provider for
the same reason: an `exit` provider would start with no key and no licence and
store every object as plaintext — a deployment that looks encrypted and is not.

Everything this file does not mention keeps the proxy's own default; the keys
and their defaults are in
[the key reference in README.md](../../README.md#configuration)
above. The file deliberately does not restate them, so there is one source for a
default rather than two that drift.

**To use your own configuration**, mount it over `/app/config/default.yaml`, or
name a path of your own: the binary is the image's `ENTRYPOINT`, so
`docker run … <image> --config /path/to/your.yaml` replaces the default
arguments and nothing else. The Helm chart takes the second route: it renders its own
configuration into a ConfigMap and points the pod at it with
`--config=/app/config/config.yaml`, so the
`S3EP_BACKEND_*` and `S3EP_CLIENT_*` variables do not apply to a chart install —
its configuration carries the endpoint and region literally and names
`${S3_ACCESS_KEY_ID}` / `${S3_SECRET_KEY}` for the credentials. `S3EP_AES_KEY`
still applies: the chart's `config` references it and the chart supplies it from
`secrets.encryption.*` or an `env` entry — see
[Kubernetes with Helm](deployment.md#kubernetes-with-helm).

How the mechanism works and where it is implemented is in
[docs/developer/configuration.md](../developer/configuration.md).

## Configuration Examples

Complete files live in the `config/` directory: `aes-example.yaml` and
`aes-tls-example.yaml` (the same setup with the proxy's own TLS listener),
`multi-example.yaml` for key rotation, and `exit-example.yaml` for the exit
provider. The encryption block of each:

### AES Envelope Configuration (`config/aes-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-envelope"
  providers:
    - alias: "aes-envelope"
      type: "aes"
      description: "AES envelope encryption"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

### Multi-Provider Configuration (`config/multi-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-current"
  providers:
    # Current encryption for new objects
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "${S3EP_AES_KEY}"

    # The retired key, still able to read what it wrote
    - alias: "aes-previous"
      type: "aes"
      description: "Retired key, kept so objects written under it stay readable"
      config:
        aes_key: "${S3EP_AES_KEY_RETIRED}"
```

### Exit Provider Configuration (`config/exit-example.yaml`)
```yaml
encryption:
  # Active: stores what the client sends, no data key, no s3ep-* metadata
  encryption_method_alias: "exit"
  providers:
    - alias: "exit"
      type: "exit"
      description: "Stores what the client sends; holds no key material"

    # Not active, never writes. Registered so that objects encrypted before the
    # switch are still decrypted: an object names the key that wrapped it in its
    # own s3ep-kek-fingerprint metadata.
    - alias: "aes-previous"
      type: "aes"
      description: "The key the objects already in the bucket were written with"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

The exit provider is the one type the startup license gate admits without a
license, because the gate looks only at the active provider. That is the point:
getting the data out must not depend on a valid license.

> No usable key is tracked in this repository (ADR 0021). Every example above
> references `${S3EP_AES_KEY}`; `scripts/gen-keys.sh` generates one into the
> ignored `.env` file, and `./start-demo.sh` calls it. An unset variable fails
> the configuration load and the proxy refuses to start — there is no default
> key and no fallback.

