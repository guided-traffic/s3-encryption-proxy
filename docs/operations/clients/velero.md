# Velero

Velero's end-to-end suite runs against the newest Velero in a local `kind`
cluster, with encryption-at-rest assertions read straight from the MinIO backend:

```bash
make e2e-up            # kind cluster + MinIO + CSI hostpath + proxy + Velero
make test-e2e-velero   # backup/restore scenarios, incl. encryption-at-rest checks
make e2e-down
```

Pinned versions live in
[`test/e2e/velero/versions.env`](../../../test/e2e/velero/versions.env) and are
tracked by Renovate as the group "Velero e2e".

## Configuration notes for a real Velero deployment


- Point the `BackupStorageLocation` at the proxy over **HTTPS** with
  `s3ForcePathStyle: "true"`. Modern AWS SDKs only emit their checksum-trailer
  request framing over TLS, and that framing is the one the proxy must decode.
- Set `publicUrl` if the `velero` CLI runs outside the cluster: pre-signed URLs
  are minted by the in-cluster server and fetched by the CLI.
- Nothing throttles Velero: the proxy performs **no request rate limiting** at
  all, so its backup bursts are not a concern. See
  [Security](../../../README.md#security) for what that means for everyone else.
- The three gaps that used to make this depend on a trusted backend are closed
  by the storage format: kopia's ranged reads of its pack blobs are verified
  segment by segment, a modified object is never delivered whole, and an object
  whose `s3ep-*` metadata has been stripped is refused rather than served.

> **⚠️ Set the kopia repository password before the first backup.**
>
> Velero creates the secret `velero-repo-credentials` with the hardcoded
> password `static-passw0rd` if that secret does not already exist
> ([`pkg/repository/keys/keys.go`](https://github.com/velero-io/velero/blob/main/pkg/repository/keys/keys.go),
> [velero#6443](https://github.com/velero-io/velero/issues/6443),
> [velero#8137](https://github.com/velero-io/velero/issues/8137)). With that
> default, kopia's AES-GCM and its content HMACs are forgeable by anyone who can
> read the bucket - the repository salt sits in `kopia.repository`, in the same
> bucket as the data - so kopia's own layer provides neither confidentiality nor
> integrity against the storage backend. Velero's other objects (the resource
> tarballs, which contain Secrets, plus logs and results) are never encrypted by
> Velero at all. This proxy is the only real protection for both, and a strong
> repository password is what makes kopia a second layer instead of a decoration.
>
> Create the secret yourself, in the Velero namespace, **before the first
> backup**:
>
> ```bash
> kubectl -n velero create secret generic velero-repo-credentials \
>   --from-literal=repository-password="$(openssl rand -base64 32)"
> ```
>
> Velero writes the secret only when it is missing, and an existing kopia
> repository keeps the password it was created with, so this cannot be fixed
> after the fact. Store the value where you store your other break-glass
> secrets: without it, existing repositories cannot be read.

