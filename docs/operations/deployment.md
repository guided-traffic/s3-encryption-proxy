# Deployment

The three supported installation paths in full: the container image, Docker
Compose, and the Helm chart. The shortest working form of each is in
[README.md](../../README.md#installation-paths); what is here is everything
beside it.

Whichever path you take, two things hold:

- **Keep the key encryption key.** An object encrypted under a key you have lost
  is not recoverable, and a fresh key on every start makes every object written
  under the previous one unreadable.
- **The key belongs in a secret, never in the rendered configuration.** The Helm
  note below says where a chart install puts it.

## Docker

### With the image's own configuration (recommended)

The image starts from `/app/config/default.yaml` and takes every value it needs
from an environment variable, so nothing has to be mounted. The seven variables
are in [The container's own configuration](configuration.md#the-containers-own-configuration);
each is mandatory and an unset one is a named startup error. Generate
`S3EP_AES_KEY` once and keep it — see
[Environment variable references](configuration.md#environment-variable-references) — because a
fresh key on every run makes every object written under the previous one
unreadable.

```bash
# Build. The build file is named Containerfile, so it has to be named too.
docker build -f Containerfile -t s3-encryption-proxy .

docker run -d \
  -p 8080:8080 \
  -e S3EP_LICENSE_TOKEN="$S3EP_LICENSE_TOKEN" \
  -e S3EP_BACKEND_ENDPOINT="https://minio:9000" \
  -e S3EP_BACKEND_REGION="us-east-1" \
  -e S3EP_BACKEND_ACCESS_KEY_ID="minioadmin" \
  -e S3EP_BACKEND_SECRET_KEY="minioadmin123" \
  -e S3EP_CLIENT_ACCESS_KEY_ID="username0" \
  -e S3EP_CLIENT_SECRET_KEY="a-secret-of-at-least-16-characters" \
  -e S3EP_AES_KEY="$S3EP_AES_KEY" \
  s3-encryption-proxy
```

### With a configuration file of your own

Mount it over the path the image starts from, or name a path of your own: the
binary is the image's `ENTRYPOINT`, so an argument you pass goes straight to it.
The shipped examples under `config/`
reference `${S3EP_AES_KEY}` and carry no key of their own (ADR 0021), so that
variable is what makes them work — see
[Environment variable references](configuration.md#environment-variable-references).

```bash
docker run -d \
  -p 8080:8080 \
  -e S3EP_LICENSE_TOKEN="$S3EP_LICENSE_TOKEN" \
  -e S3EP_AES_KEY="$S3EP_AES_KEY" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

## Docker Compose

```yaml
version: '3.8'
services:
  s3-encryption-proxy:
    image: guidedtraffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics, only with monitoring.enabled
    # No volume and no command: the image starts from its own configuration.
    environment:
      - S3EP_LICENSE_TOKEN=${S3EP_LICENSE_TOKEN}
      - S3EP_BACKEND_ENDPOINT=https://minio:9000
      - S3EP_BACKEND_REGION=us-east-1
      - S3EP_BACKEND_ACCESS_KEY_ID=${S3EP_BACKEND_ACCESS_KEY_ID}
      - S3EP_BACKEND_SECRET_KEY=${S3EP_BACKEND_SECRET_KEY}
      - S3EP_CLIENT_ACCESS_KEY_ID=${S3EP_CLIENT_ACCESS_KEY_ID}
      - S3EP_CLIENT_SECRET_KEY=${S3EP_CLIENT_SECRET_KEY}
      - S3EP_AES_KEY=${S3EP_AES_KEY}
```

## Kubernetes with Helm

```bash
# The chart lives in deploy/helm/s3-encryption-proxy and ships values files for
# development, production and monitoring.
cd deploy/helm/s3-encryption-proxy
helm install s3-encryption-proxy . \
  --values values-production.yaml \
  --set-file config=../../../config/aes-example.yaml

# deploy/helm/install.sh is a wrapper around the same thing. It takes no
# positional argument, only --dry-run, --upgrade and --help.
```

> The chart injects the master key; it never wants it in the configuration. The
> proxy configuration is rendered from the single `config` value straight into a
> ConfigMap, so a key written **there** is stored in clear text and readable by
> anyone with `get configmaps` in the namespace. Reference it as
> `${S3EP_AES_KEY}` inside `config` instead and point the chart at a Secret you
> manage: `secrets.encryption.existingSecret` with `secrets.encryption.existingSecretKey`,
> or an `env` entry with a `secretKeyRef` — the shipped `values-production.yaml`
> is written the second way and only the secret name has to change.
> (`secrets.encryption.aesKey` works too, but it puts the key into the chart's
> own Secret and therefore into whatever holds your values file.) The license is
> different: `license.existingSecret` (or `license.jwt`) mounts it and points
> `license_file` at the mount. See the chart's own
> [README](../../deploy/helm/s3-encryption-proxy/README.md).

> **One instance per release, and the chart refuses a second.** `replicaCount`
> above 1 and `autoscaling.enabled: true` both fail the render. A client-driven
> multipart upload is held in the process that answered `CreateMultipartUpload`
> — its part table and the object's data key live there and nowhere else — so a
> part balanced onto another pod is answered `404 NoSuchUpload`, and nothing in
> the chart makes a client stay on one pod: the Service sets no session affinity
> and the default Ingress annotations carry none. A second replica does not take
> a share of the work, it takes requests belonging to an upload the first one is
> holding. Proxies that share an upload between them are a change to the proxy
> itself — a session table the instances read — and not a replica count
> ([ADR 0033](../adr/0033-a-proxy-instance-holds-its-uploads.md)).

Example custom values (the shipped `values-production.yaml` sets different
resource numbers; this block shows the keys, not that file):

```yaml
replicaCount: 1        # anything above 1 fails the render

autoscaling:
  enabled: false       # refused as well: an autoscaler is a second replica

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

