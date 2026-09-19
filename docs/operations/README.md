# Operating the proxy

Reference for the people who run this proxy and for the clients that talk to it.
[README.md](../../README.md) is the short version — what the product is, how to
start it, which clients are supported. Everything it links to for detail is here.

| Page | Read it when |
|---|---|
| [configuration.md](configuration.md) | You are writing the configuration file: the settings that need explaining, `${VAR}` references, the container image's own configuration, the shipped examples |
| [deployment.md](deployment.md) | You are installing: the container image, Docker Compose, the Helm chart |
| [s3-api.md](s3-api.md) | A client behaves differently against the proxy than against plain S3: ranges, listings, conditional requests, pre-signed URLs, sub-resources, what a read costs |
| [integrity.md](integrity.md) | You need to know what is guaranteed about the bytes: the stored format, the metadata, foreign objects, checksums, entity tags |
| [monitoring.md](monitoring.md) | You are wiring up Prometheus, probes or the `/status` document |
| [upgrading.md](upgrading.md) | You are coming from 3.x or 4.x. **Read it before you upgrade** — stored objects and configuration files both break |
| [clients/](clients/) | You run Velero, rclone or s3cmd against the proxy |

## Supported clients

Each has an end-to-end suite that runs against a pinned release of the real
client, and a page of the settings a real deployment needs.

| Client | Page | Suite |
|---|---|---|
| Velero | [clients/velero.md](clients/velero.md) | `make e2e-velero` |
| rclone | [clients/rclone.md](clients/rclone.md) | `make e2e-rclone` |
| s3cmd | [clients/s3cmd.md](clients/s3cmd.md) | `make e2e-s3cmd` |

Any other S3 client is in scope as well — the AWS CLI, the SDKs, CNPG Barman —
and compatibility is argued from S3 semantics rather than from one observed
client ([ADR 0006](../adr/0006-the-proxy-serves-any-s3-client.md)). The three
above are the ones a suite proves on every release.

## The other documentation

| Where | What |
|---|---|
| [README.md](../../README.md) | What the product is, the fast start, the complete configuration key reference |
| [docs/security/](../security/) | Threat model, trust boundaries, where keys live, and the gap each mechanism leaves |
| [docs/adr/](../adr/) | Why the product behaves the way it does, and what was rejected |
| [docs/developer/](../developer/) | Changing the code: package map, request paths, the codec, tests |
