# Key Material and Deployment Secrets

> 52 nodes · cohesion 0.06

## Key Concepts

- **S3 Encryption Proxy README** (55 connections) — `README.md`
- **ADR 0021: Key material is generated, never committed** (23 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **Operations: Configuration guide** (17 connections) — `docs/operations/configuration.md`
- **Operating the proxy (operations index)** (13 connections) — `docs/operations/README.md`
- **Operations: Deployment** (12 connections) — `docs/operations/deployment.md`
- **s3cmd** (9 connections) — `docs/operations/clients/s3cmd.md`
- **Operations: Upgrading** (9 connections) — `docs/operations/upgrading.md`
- **rclone** (8 connections) — `docs/operations/clients/rclone.md`
- **Graceful shutdown ends open uploads** (6 connections) — `docs/operations/configuration.md`
- **One instance per release; the chart refuses a second** (5 connections) — `docs/operations/deployment.md`
- **What the proxy guarantees about your bytes** (5 connections) — `docs/operations/integrity.md`
- **secrets.encryption.* and secrets.s3.* injection** (4 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **optimizations.multipart_session_idle_timeout** (4 connections) — `docs/operations/configuration.md`
- **Helm chart install** (4 connections) — `docs/operations/deployment.md`
- **Three installation paths** (4 connections) — `docs/operations/deployment.md`
- **S3EP_AES_KEY as the one key variable name** (3 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- **use_multipart_etag = false** (3 connections) — `docs/operations/clients/rclone.md`
- **s3cmd compares every PUT and part ETag with its MD5** (3 connections) — `docs/operations/clients/s3cmd.md`
- **config/default.yaml (the image's own configuration)** (3 connections) — `docs/operations/configuration.md`
- **${VAR} environment reference mechanism** (3 connections) — `docs/operations/configuration.md`
- **Shipped configuration examples** (3 connections) — `docs/operations/configuration.md`
- **Docker run with the image's own configuration** (3 connections) — `docs/operations/deployment.md`
- **The KEK belongs in a Secret, never in the ConfigMap** (3 connections) — `docs/operations/deployment.md`
- **Within 5.x: the release that stops checking a licence** (3 connections) — `docs/operations/upgrading.md`
- **Key material generated on demand into ignored .env** (2 connections) — `docs/adr/0021-key-material-is-generated-never-committed.md`
- *... and 27 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (19 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (19 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (16 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (12 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (9 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (6 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (3 shared connections)
- [Etag: Etag](Etag-_Etag.md) (2 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (2 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (1 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)

## Source Files

- `README.md`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/adr/0021-key-material-is-generated-never-committed.md`
- `docs/operations/README.md`
- `docs/operations/clients/rclone.md`
- `docs/operations/clients/s3cmd.md`
- `docs/operations/configuration.md`
- `docs/operations/deployment.md`
- `docs/operations/integrity.md`
- `docs/operations/upgrading.md`

## Audit Trail

- EXTRACTED: 157 (92%)
- INFERRED: 12 (7%)
- AMBIGUOUS: 1 (1%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*