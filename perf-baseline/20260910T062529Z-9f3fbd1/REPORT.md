# Performance baseline — upload path decomposition

Run `20260910T062529Z-9f3fbd1`, schema 1. 2026-09-10T06:25:29Z → 2026-09-10T06:25:36Z (8 s), 7 repetitions per point.

Commit `9f3fbd11351fd769ef69c602df80cb6548717e4c` on `feat/major-v5` **(working tree dirty)**.

## Machine

| Property | Value |
|---|---|
| CPU | Apple M5 Pro |
| Cores | 18 physical / 18 logical, GOMAXPROCS 18 |
| Memory | 64 GiB |
| OS | darwin 26.6.2 (Darwin 25.6.0) |
| Arch | arm64 |
| Go | go1.27.1 |
| Docker | Docker version 29.6.2, build dfc4efb |
| Power source | battery |
| Load average before | 1.77 / 1.59 / 1.59 |
| Load average after | 1.97 / 1.63 / 1.61 |

## Stack

| Property | Value |
|---|---|
| endpoint minio | https://127.0.0.1:9000 |
| endpoint proxy_http | http://127.0.0.1:8080 |
| endpoint proxy_tls | https://127.0.0.1:8443 |
| image minio | minio/minio:latest |
| image proxy | s3-encryption-proxy-s3-encryption-proxy |
| image proxy_tls | s3-encryption-proxy-s3-encryption-proxy-tls |
| config integrity_verification | strict |
| config multipart_upload_concurrency | 4 |
| config provider_type | aes |
| config streaming_segment_size | 12582912 |
| config streaming_threshold | 5242880 |

## Instruments

| Instrument | Status | Reason |
|---|---|---|
| selfcopy | ok | single-leg profiling harness, not a gate |
| uploadpath | ok | — |

## Upload write paths — streaming against auto-multipart

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | upload | 8 MiB | proxy | 97.4 | 164.9 | 59.0 % | 2.9 % | yes |
| http | upload | 8 MiB | proxy-streaming | 173.5 | 164.9 | 105.2 % | 3.0 % | yes |
| http | upload | 12 MiB | proxy | 95.3 | 165.8 | 57.5 % | 3.5 % | yes |
| http | upload | 12 MiB | proxy-streaming | 172.8 | 165.8 | 104.2 % | 10.8 % | **no** |
| http | upload | 16 MiB | proxy | 115.3 | 165.1 | 69.8 % | 5.9 % | yes |
| http | upload | 16 MiB | proxy-streaming | 184.4 | 165.1 | 111.7 % | 4.1 % | yes |

## Backend self-copy (single-leg profiling harness)

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| backend | self_copy_replace | 8 MiB | 4826 | MiB/s | 7.4 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |
| backend | self_copy_replace | 32 MiB | 6587 | MiB/s | 7.6 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |
| backend | self_copy_replace | 128 MiB | 7485 | MiB/s | 7.8 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
