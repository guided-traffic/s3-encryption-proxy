# Configuration: where a value comes from

Three mechanisms decide what the proxy runs on, and only three. This page says
what each one is for and where it is implemented, because the interesting part
is what is **not** here: there is no fourth, and no value can be changed from
outside the file that declares it.

## Where the file comes from

`InitConfig` (`internal/config/config.go`) takes the path from `--config` when
it is given. Without the flag it searches `$HOME`, the working directory and
`./config` for `.s3-encryption-proxy.yaml`.

The container does not rely on that search. Its `CMD` passes
`--config config/default.yaml`, and `WORKDIR` is `/app`, so the image starts
from **`/app/config/default.yaml`** — [`config/default.yaml`](../../config/default.yaml)
in this repository. An operator replaces it by mounting over that path or by
passing a `--config` of their own; the Helm chart does neither and renders its
own configuration into a ConfigMap.

## 1. Defaults

`setDefaults` writes every default into viper before the file is read, so a key
the file omits has one value and it lives in one place. A default that also
appears in a shipped YAML file is two sources that drift — that is why
`config/default.yaml` carries only what has no default.

## 2. The file

`Load` unmarshals with `ErrorUnused`, so a key the proxy does not define refuses
the start and the error names it (ADR 0013 D11). A misspelling is caught by the
same mechanism. Two keys are checked before the unmarshal because their meaning
changed rather than disappearing — `optimizations.multipart_session_max_age` and
a `multipart_session_idle_timeout` below 1 — so the operator reads about the
change once instead of inferring it from behaviour.

## 3. `${VAR}` references inside a value

`expandConfigEnvVars` (`internal/config/envexpand.go`) resolves `${VAR}` in a
**named list of fields**, after the unmarshal and before validation:

- `s3_backend.target_endpoint`, `s3_backend.region`
- `s3_backend.access_key_id`, `s3_backend.secret_key`
- `s3_clients[].access_key_id`, `s3_clients[].secret_key`
- every string value under `encryption.providers[].config`

The list is per field rather than "every string" so that a value where a `$` is
legitimate — a secret, above all — is never rewritten. Bare `$VAR` is not
expanded for the same reason.

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
