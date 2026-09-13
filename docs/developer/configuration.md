# Configuration: where a value comes from

Three mechanisms decide what the configuration file says, and only three. This
page says what each one is for and where it is implemented, because the
interesting part is what is **not** here: no configuration key is bound to an
environment variable, so a key written in the file is changed in the file.

One thing reaches the proxy from outside the file, and it is named here so that
list stays honest: the license token is read from `S3EP_LICENSE`,
`S3EP_LICENSE_TOKEN` or `S3_ENCRYPTION_PROXY_LICENSE`, in that order, before
`license_file` is opened — during validation, where it decides whether an
encrypting provider may be used at all. Nothing else does. The binary declares
one flag, `--config`; the `--monitoring` and `--monitoring-port` flags that used
to overrule `monitoring.enabled` and `monitoring.bind_address` are gone, and the
Helm chart renders a `monitoring:` block into its ConfigMap instead
(ADR 0013 D14).

## Where the file comes from

`InitConfig` (`internal/config/config.go`) takes the path from `--config` when
it is given. Without the flag it searches `$HOME`, the working directory and
`./config` for `.s3-encryption-proxy.yaml`.

A file the loader cannot read or parse refuses the start, and the error names it
(ADR 0013 D12): `InitConfig` returns the `ReadInConfig` error and `initConfig`
in `main.go` is fatal on it. A mistyped `--config` path and a malformed YAML
mounted over `/app/config/default.yaml` are both reported as what they are;
before, they left the proxy on defaults alone and what the operator saw was
`config validation failed: s3_backend.target_endpoint is required` — a key their
file may well have set. Finding no file in the search path is the one case that
stays tolerant: nothing was named, so nothing was misread, and the start then
fails on the keys that have no default.

The container does not rely on that search. Its `CMD` passes
`--config config/default.yaml`, and `WORKDIR` is `/app`, so the image starts
from **`/app/config/default.yaml`** — [`config/default.yaml`](../../config/default.yaml)
in this repository. An operator replaces it by mounting over that path or by
passing a `--config` of their own; the Helm chart does both — it renders its own
configuration into a ConfigMap, mounts it at `/app/config`, which shadows the
image's `default.yaml`, and starts the container with
`--config=/app/config/config.yaml`. A chart install therefore runs on the
chart's own `${VAR}` set, which overlaps the image's seven only in
`S3EP_AES_KEY`.

## 1. Defaults

`setDefaults` writes the defaults into viper before the file is read, so a key
the file omits still has a value. Two things qualify that. `shutdown_timeout`
has no viper default at all — its 30-second fallback lives in the two places in
the binary that consume it, the shutdown path in `main.go` and
`Server.shutdownBudget`, and again in the Helm chart, whose
`terminationGracePeriodSeconds` helper derives the pod's grace period from the
same key and falls back to 30 as well. And `streaming_segment_size`,
`multipart_upload_concurrency` and `encryption.metadata_key_prefix` restate their
default as a literal at the point of use as well. `setDefaults` fills all three,
so an omitted key never reaches those branches — but a written `0` does: a value
in the file beats a viper default, and `validateOptimizations` range-checks only
a non-zero value, so `streaming_segment_size: 0` and
`multipart_upload_concurrency: 0` pass validation and are then replaced by the
literal at the point of use, which is the silent fixup ADR 0017 D8 rules out.
`encryption.metadata_key_prefix` has no such hole: an explicit empty string is
non-nil and is refused by the prefix pattern.

A default that also appears in a shipped YAML file is two sources that drift, so
`config/default.yaml` restates no default value. It does name one key that has a
default — `s3_backend.region`, `us-east-1` in `setDefaults` — as
`${S3EP_BACKEND_REGION}`, because the image asks a deployment for its region
rather than assuming it, and naming the key there makes that variable mandatory.
The other six references are keys with no default at all.

## 2. The file

`Load` unmarshals with `ErrorUnused`, so a key the proxy does not define refuses
the start and the error names it (ADR 0013 D11). A misspelling is caught by the
same mechanism, with the one boundary described below. Two checks run before the
unmarshal, for two different reasons.
`optimizations.multipart_session_max_age` is refused by name because its meaning
moved into `multipart_session_idle_timeout` rather than disappearing — the same
number counts from the last part now, not from the session's creation — so the
operator reads about the change once instead of inferring it from behaviour. A
`multipart_session_idle_timeout` below 1 is refused there because `setDefaults`
fills 3600: in the decoded struct an absent key and a written 0 look the same,
so the check reads `viper.IsSet` to see what the configuration actually wrote
(ADR 0017 D8 — a value that switches a check off is refused by name, never
quietly replaced).

Two more keys are checked there for the same reason and in the same shape.
`multipart_session_cleanup_interval` below 1 would leave nothing to reclaim an
abandoned session, and `max_request_document_size` below 1 would mean no bound at
all on a request document the proxy has to buffer whole (ADR 0024 D8). Both read
`viper.InConfig`, not `IsSet`: viper consults its own defaults for `IsSet`, which
is true for every key `setDefaults` fills, while `InConfig` asks the parsed file —
which is the question these three checks are asking.

`ErrorUnused` has one boundary, and it is pinned by a test: a provider block
swallows its own parameters. `EncryptionProvider` carries a `,remain` field, and
mapstructure clears the unused-key set before it applies the check, so an
unknown key under `encryption.providers[]` — or anything inside its `config:` —
never reaches it. `createProviderFromProviderMap` then reads `alias`, `type`,
`description` and `config` and drops the rest. A misspelt provider parameter
therefore loads in silence: under an `aes` provider it surfaces only as the
missing `aes_key` that `validateAESKey` refuses, and under `exit` it does not
surface at all.

## 3. `${VAR}` references inside a value

`expandConfigEnvVars` (`internal/config/envexpand.go`) resolves `${VAR}` in a
**named list of fields**, after the unmarshal and before validation:

- `s3_backend.target_endpoint`, `s3_backend.region`
- `s3_backend.access_key_id`, `s3_backend.secret_key`
- `s3_clients[].access_key_id`, `s3_clients[].secret_key`
- every string value directly under `encryption.providers[].config` — a nested
  map is skipped, not descended into

The list is per field rather than "every string" so that a value the loader has
no business rewriting — a certificate path, a description, a metadata prefix —
is left as written. The credentials are on the list deliberately, and that has a
price worth knowing: a secret containing a literal `${...}` cannot be carried in
these fields, because it would be substituted or refuse the start as an unset
variable. Bare `$VAR` is not expanded, which keeps a `$` in a secret harmless.

An unset **or empty** variable is an error naming the field and the variable.
That is the property `config/default.yaml` is built on: every value it needs is
a reference, so the image cannot start half-configured, with an empty credential
or without a key. `internal/config/default_config_test.go` asserts it one
variable at a time, and asserts the variable set itself, which is a documented
interface — `README.md` carries the same table.

## What was removed in 5.0.0, and why it matters here

Until 5.0.0 `InitConfig` also called `viper.AutomaticEnv()` with the `S3EP`
prefix. That bound **every** configuration key to an environment variable and
let it win over the file:

| Variable | Overrode | Consequence |
|---|---|---|
| `S3EP_S3_BACKEND.INSECURE_SKIP_VERIFY` | `false` in the file | The certificate check to the backend, off |
| `S3EP_MONITORING.PPROF_ENABLED` | `false` in the file | A heap endpoint on a process holding the KEK, DEKs and plaintext |
| `S3EP_ENCRYPTION.METADATA_KEY_PREFIX` | `s3ep-` in the file | The proxy's namespace moved; every stored object unreadable |

An operator read one thing in the ConfigMap and something else was in force,
with nothing in the file or the log to say so — and a misspelt variable was
ignored in exactly the silence ADR 0013 D11 removed for the file. The syntax
made it worse rather than better: the separator had to be a dot
(`S3EP_S3_BACKEND.INSECURE_SKIP_VERIFY`), and the underscore form every operator
would try did nothing at all. Deliberate use mostly failed; accidental use
succeeded.

`internal/config/loading_coverage_test.go` pins the removal, including the three
security controls above.

## Related

- [README: the container's own configuration](../../README.md#the-containers-own-configuration) — the operator-facing variable table
- [README: complete configuration file structure](../../README.md#complete-configuration-file-structure) — every key and its default
- [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) — a key exists only if code reads it, and an unknown one refuses the start
- [ADR 0021](../adr/0021-key-material-is-generated-never-committed.md) — key material is generated, never committed
