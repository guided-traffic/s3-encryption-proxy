# Performance baseline — segment-codec, item 1

Run `20260909T212247Z-9f3fbd1`, schema 1. 2026-09-09T21:22:47Z → 2026-09-09T21:22:51Z (4 s), 7 repetitions per point.

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
| Power source | AC |
| Load average before | 3.02 / 4.76 / 3.60 |
| Load average after | 3.02 / 4.73 / 3.60 |

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
| cryptofloor | ok | — |
| unwrap | ok | — |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 117.8 | ns/op | 5.4 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 594734 | ns/op | 0.3 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3597584 | ns/op | 0.5 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 296.2 | ns/op | 1.7 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 19238 | ns/op | 2.0 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 91653 | ns/op | 0.8 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | crc32c | 64 KiB | 7812 | MiB/s | 8.9 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 1 MiB | 10426 | MiB/s | 1.9 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 12 MiB | 11608 | MiB/s | 1.0 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 128 MiB | 11614 | MiB/s | 0.2 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | ctr_encrypt | 64 KiB | 7076 | MiB/s | 51.2 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 1 MiB | 8889 | MiB/s | 3.8 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 12 MiB | 10805 | MiB/s | 2.8 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 128 MiB | 11266 | MiB/s | 0.4 % | 7 | AES-CTR only |
| in-process | hmac_only | 64 KiB | 2508 | MiB/s | 6.0 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 1 MiB | 2712 | MiB/s | 1.5 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 12 MiB | 3311 | MiB/s | 0.5 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 128 MiB | 3308 | MiB/s | 0.1 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | v1_ctr_hmac_decrypt | 64 KiB | 1786 | MiB/s | 26.5 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 1 MiB | 2216 | MiB/s | 2.6 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 12 MiB | 2564 | MiB/s | 1.5 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 128 MiB | 2538 | MiB/s | 1.3 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 64 KiB | 1974 | MiB/s | 6.9 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 1 MiB | 2147 | MiB/s | 2.7 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 12 MiB | 2558 | MiB/s | 0.5 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 128 MiB | 2561 | MiB/s | 0.2 % | 7 | current write path above the threshold |
| in-process | v1_gcm_whole_decrypt | 64 KiB | 7854 | MiB/s | 0.9 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 1 MiB | 8172 | MiB/s | 0.1 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 12 MiB | 9455 | MiB/s | 3.7 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 128 MiB | 9349 | MiB/s | 3.1 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_encrypt | 64 KiB | 6667 | MiB/s | 8.9 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 1 MiB | 7590 | MiB/s | 0.1 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 12 MiB | 8797 | MiB/s | 2.1 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 128 MiB | 8824 | MiB/s | 3.2 % | 7 | current write path below the threshold |
| in-process | v2_codec_decrypt | 64 KiB | 2027 | MiB/s | 50.4 % | 7 | the shipped segment codec, trailer verified |
| in-process | v2_codec_decrypt | 1 MiB | 3964 | MiB/s | 15.2 % | 7 | the shipped segment codec, trailer verified |
| in-process | v2_codec_decrypt | 12 MiB | 4502 | MiB/s | 3.8 % | 7 | the shipped segment codec, trailer verified |
| in-process | v2_codec_decrypt | 128 MiB | 4486 | MiB/s | 2.7 % | 7 | the shipped segment codec, trailer verified |
| in-process | v2_codec_encrypt | 64 KiB | 2216 | MiB/s | 14.6 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | v2_codec_encrypt | 1 MiB | 4023 | MiB/s | 2.5 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | v2_codec_encrypt | 12 MiB | 4474 | MiB/s | 1.6 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | v2_codec_encrypt | 128 MiB | 4452 | MiB/s | 0.5 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | v2_gcm_seg_decrypt | 64 KiB | 6522 | MiB/s | 8.5 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 1 MiB | 8403 | MiB/s | 0.3 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 12 MiB | 9356 | MiB/s | 3.0 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 128 MiB | 9288 | MiB/s | 3.5 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 64 KiB | 6000 | MiB/s | 9.3 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 1 MiB | 7742 | MiB/s | 0.6 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 12 MiB | 8668 | MiB/s | 0.8 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 128 MiB | 8706 | MiB/s | 0.4 % | 7 | segmented AES-GCM candidate, 64 KiB segments |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
