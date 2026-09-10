# Performance baseline — pre-v2-uploadpath

Run `20260910T090543Z-530472c`, schema 1. 2026-09-10T09:05:43Z → 2026-09-10T09:06:25Z (42 s), 7 repetitions per point.

Commit `530472c84c8438c01e126283201088a74a4ae9c5` on `feat/major-v5`.

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
| Power source | AC |
| Load average before | 1.02 / 1.15 / 1.33 |
| Load average after | 2.36 / 1.47 / 1.44 |

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
| http | upload | 8 MiB | proxy | 89.9 | 154.9 | 58.1 % | 6.3 % | yes |
| http | upload | 8 MiB | proxy-streaming | 164.7 | 154.9 | 106.3 % | 5.6 % | yes |
| http | upload | 12 MiB | proxy | 85.4 | 159.2 | 53.6 % | 4.9 % | yes |
| http | upload | 12 MiB | proxy-streaming | 167.7 | 159.2 | 105.3 % | 6.0 % | yes |
| http | upload | 16 MiB | proxy | 108.3 | 164.0 | 66.1 % | 3.6 % | yes |
| http | upload | 16 MiB | proxy-streaming | 170.8 | 164.0 | 104.1 % | 5.6 % | yes |
| http | upload | 24 MiB | proxy | 109.3 | — | — | 3.1 % | yes |
| http | upload | 24 MiB | proxy-streaming | 178.9 | — | — | 5.5 % | yes |
| http | upload | 64 MiB | proxy | 125.3 | — | — | 1.7 % | yes |
| http | upload | 64 MiB | proxy-streaming | 190.2 | — | — | 6.2 % | yes |
| http | upload | 256 MiB | proxy | 139.2 | — | — | 1.0 % | yes |
| http | upload | 256 MiB | proxy-streaming | 201.4 | — | — | 2.0 % | yes |

## Backend self-copy (single-leg profiling harness)

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| backend | self_copy_replace | 8 MiB | 4267 | MiB/s | 14.4 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |
| backend | self_copy_replace | 32 MiB | 5553 | MiB/s | 13.8 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |
| backend | self_copy_replace | 128 MiB | 8325 | MiB/s | 6.5 % | 7 | server-side CopyObject onto itself with MetadataDirective=REPLACE, the operation the proxy runs after every multipart completion |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
