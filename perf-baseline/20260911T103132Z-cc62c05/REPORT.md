# Performance baseline — post-v2-wave5

Run `20260911T103132Z-cc62c05`, schema 1. 2026-09-11T10:31:32Z → 2026-09-11T10:38:32Z (421 s), 7 repetitions per point.

Commit `cc62c055a8035918a9c84102b5fc7a443bafcffe` on `feat/major-v5` **(working tree dirty)**.

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
| Load average before | 3.34 / 5.09 / 4.51 |
| Load average after | 7.12 / 6.66 / 5.46 |

## Stack

| Property | Value |
|---|---|
| endpoint minio | https://127.0.0.1:9000 |
| endpoint proxy_http | http://127.0.0.1:8080 |
| endpoint proxy_tls | https://127.0.0.1:8443 |
| image minio | minio/minio:latest |
| image proxy | s3-encryption-proxy-s3-encryption-proxy |
| image proxy_tls | s3-encryption-proxy-s3-encryption-proxy-tls |
| config multipart_upload_concurrency | 4 |
| config provider_type | aes |
| config streaming_segment_size | 12582912 |

## Instruments

| Instrument | Status | Reason |
|---|---|---|
| cryptofloor | ok | — |
| memory | ok | — |
| profiles | ok | — |
| rangeread | ok | — |
| smallobject | ok | — |
| throughput | ok | — |
| unwrap | ok | — |
| uploadpath | ok | — |

## Throughput — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | download | 1 KiB | proxy | 1.1 | 2.0 | 54.4 % | 14.0 % | **no** |
| http | download | 64 KiB | proxy | 63.1 | 89.1 | 70.9 % | 6.1 % | yes |
| http | download | 256 KiB | proxy | 117.8 | 182.7 | 64.5 % | 11.1 % | **no** |
| http | download | 1 MiB | proxy | 184.0 | 225.2 | 81.7 % | 5.9 % | yes |
| http | download | 4 MiB | proxy | 233.6 | 250.5 | 93.2 % | 11.7 % | **no** |
| http | download | 5 MiB | proxy | 227.9 | 239.6 | 95.1 % | 6.1 % | yes |
| http | download | 8 MiB | proxy | 238.3 | 246.7 | 96.6 % | 6.2 % | yes |
| http | download | 32 MiB | proxy | 255.1 | 249.6 | 102.2 % | 1.2 % | yes |
| http | download | 128 MiB | proxy | 259.5 | 251.7 | 103.1 % | 3.2 % | yes |
| http | upload | 1 KiB | proxy | 0.2 | 0.2 | 114.2 % | 48.0 % | **no** |
| http | upload | 64 KiB | proxy | 24.0 | 23.4 | 102.6 % | 34.2 % | **no** |
| http | upload | 256 KiB | proxy | 52.3 | 66.8 | 78.2 % | 50.5 % | **no** |
| http | upload | 1 MiB | proxy | 98.1 | 105.5 | 93.0 % | 31.1 % | **no** |
| http | upload | 4 MiB | proxy | 150.0 | 136.9 | 109.5 % | 6.0 % | **no** |
| http | upload | 5 MiB | proxy | 162.1 | 145.8 | 111.1 % | 35.0 % | **no** |
| http | upload | 8 MiB | proxy | 162.5 | 152.2 | 106.8 % | 5.6 % | yes |
| http | upload | 32 MiB | proxy | 173.5 | 209.2 | 82.9 % | 27.4 % | **no** |
| http | upload | 128 MiB | proxy | 231.1 | 240.5 | 96.1 % | 2.9 % | yes |
| tls | download | 1 KiB | proxy | 1.5 | 2.7 | 56.0 % | 17.8 % | **no** |
| tls | download | 64 KiB | proxy | 63.2 | 99.6 | 63.4 % | 11.0 % | **no** |
| tls | download | 256 KiB | proxy | 111.1 | 174.6 | 63.6 % | 11.7 % | **no** |
| tls | download | 1 MiB | proxy | 182.6 | 213.7 | 85.4 % | 6.0 % | yes |
| tls | download | 4 MiB | proxy | 230.5 | 240.8 | 95.7 % | 1.9 % | yes |
| tls | download | 5 MiB | proxy | 228.6 | 238.0 | 96.1 % | 3.0 % | yes |
| tls | download | 8 MiB | proxy | 240.3 | 247.9 | 96.9 % | 10.5 % | **no** |
| tls | download | 32 MiB | proxy | 256.9 | 249.8 | 102.8 % | 7.6 % | yes |
| tls | download | 128 MiB | proxy | 253.6 | 249.1 | 101.8 % | 2.3 % | yes |
| tls | upload | 1 KiB | proxy | 0.5 | 0.8 | 64.2 % | 37.6 % | **no** |
| tls | upload | 64 KiB | proxy | 30.5 | 39.8 | 76.6 % | 30.1 % | **no** |
| tls | upload | 256 KiB | proxy | 86.4 | 71.5 | 120.7 % | 15.8 % | **no** |
| tls | upload | 1 MiB | proxy | 135.1 | 111.1 | 121.6 % | 18.5 % | **no** |
| tls | upload | 4 MiB | proxy | 182.1 | 145.2 | 125.4 % | 2.9 % | yes |
| tls | upload | 5 MiB | proxy | 175.7 | 146.0 | 120.3 % | 7.5 % | **no** |
| tls | upload | 8 MiB | proxy | 164.7 | 155.3 | 106.0 % | 10.9 % | **no** |
| tls | upload | 32 MiB | proxy | 182.9 | 220.1 | 83.1 % | 5.1 % | yes |
| tls | upload | 128 MiB | proxy | 237.7 | 246.8 | 96.3 % | 4.0 % | yes |

## Ranged read — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | range_mid_aligned | 64 KiB | proxy | 48.7 | 67.6 | 72.0 % | 6.3 % | **no** |
| http | range_mid_aligned | 1 MiB | proxy | 207.0 | 224.9 | 92.1 % | 6.6 % | yes |
| http | range_mid_aligned | 8 MiB | proxy | 253.8 | 249.4 | 101.8 % | 3.1 % | yes |
| http | range_mid_unaligned | 64 KiB | proxy | 52.8 | 80.2 | 65.9 % | 10.5 % | **no** |
| http | range_mid_unaligned | 1 MiB | proxy | 217.0 | 228.6 | 95.0 % | 6.1 % | yes |
| http | range_mid_unaligned | 8 MiB | proxy | 249.5 | 248.2 | 100.5 % | 2.9 % | yes |
| http | range_start | 64 KiB | proxy | 37.4 | 56.5 | 66.3 % | 10.2 % | **no** |
| http | range_start | 1 MiB | proxy | 200.2 | 228.6 | 87.6 % | 4.6 % | yes |
| http | range_start | 8 MiB | proxy | 258.4 | 247.8 | 104.3 % | 5.0 % | yes |
| http | range_tail | 64 KiB | proxy | 47.5 | 71.5 | 66.5 % | 8.5 % | yes |
| http | range_tail | 1 MiB | proxy | 189.7 | 227.6 | 83.4 % | 8.3 % | yes |
| http | range_tail | 8 MiB | proxy | 252.6 | 247.2 | 102.2 % | 2.5 % | yes |
| tls | range_mid_aligned | 64 KiB | proxy | 50.0 | 65.2 | 76.6 % | 6.7 % | yes |
| tls | range_mid_aligned | 1 MiB | proxy | 199.2 | 212.8 | 93.6 % | 7.5 % | yes |
| tls | range_mid_aligned | 8 MiB | proxy | 245.6 | 244.5 | 100.4 % | 2.9 % | yes |
| tls | range_mid_unaligned | 64 KiB | proxy | 58.0 | 76.5 | 75.8 % | 3.9 % | yes |
| tls | range_mid_unaligned | 1 MiB | proxy | 194.8 | 218.1 | 89.3 % | 9.8 % | yes |
| tls | range_mid_unaligned | 8 MiB | proxy | 250.1 | 240.6 | 104.0 % | 7.1 % | yes |
| tls | range_start | 64 KiB | proxy | 39.5 | 59.7 | 66.1 % | 9.3 % | yes |
| tls | range_start | 1 MiB | proxy | 198.9 | 216.5 | 91.9 % | 5.3 % | yes |
| tls | range_start | 8 MiB | proxy | 236.6 | 250.1 | 94.6 % | 6.4 % | yes |
| tls | range_tail | 64 KiB | proxy | 52.5 | 69.8 | 75.2 % | 7.4 % | yes |
| tls | range_tail | 1 MiB | proxy | 194.0 | 221.2 | 87.7 % | 15.5 % | **no** |
| tls | range_tail | 8 MiB | proxy | 237.9 | 244.9 | 97.1 % | 3.4 % | yes |

## Small objects — request rate

| Transport | Operation | Size | Subject | ops/s | direct (ops/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | get_rate_c1 | 1 KiB | proxy | 1506.9 | 2893.4 | 52.1 % | 5.0 % | yes |
| http | get_rate_c1 | 16 KiB | proxy | 1415.2 | 2487.2 | 56.9 % | 4.6 % | yes |
| http | get_rate_c1 | 64 KiB | proxy | 1079.1 | 1654.3 | 65.2 % | 4.0 % | yes |
| http | get_rate_c32 | 1 KiB | proxy | 2623.8 | 8155.3 | 32.2 % | 28.3 % | **no** |
| http | get_rate_c32 | 16 KiB | proxy | 3208.5 | 6445.1 | 49.8 % | 14.8 % | **no** |
| http | get_rate_c32 | 64 KiB | proxy | 2265.6 | 2977.7 | 76.1 % | 15.5 % | **no** |
| http | get_rate_c8 | 1 KiB | proxy | 3668.1 | 9040.6 | 40.6 % | 15.5 % | **no** |
| http | get_rate_c8 | 16 KiB | proxy | 3916.6 | 6916.9 | 56.6 % | 13.0 % | **no** |
| http | get_rate_c8 | 64 KiB | proxy | 2380.9 | 3556.0 | 67.0 % | 9.1 % | **no** |
| http | put_rate_c1 | 1 KiB | proxy | 520.8 | 526.5 | 98.9 % | 10.4 % | **no** |
| http | put_rate_c1 | 16 KiB | proxy | 557.7 | 680.4 | 82.0 % | 11.7 % | **no** |
| http | put_rate_c1 | 64 KiB | proxy | 451.0 | 527.9 | 85.4 % | 7.9 % | **no** |
| http | put_rate_c32 | 1 KiB | proxy | 1164.6 | 1565.6 | 74.4 % | 6.7 % | **no** |
| http | put_rate_c32 | 16 KiB | proxy | 1118.5 | 1222.2 | 91.5 % | 7.1 % | yes |
| http | put_rate_c32 | 64 KiB | proxy | 843.4 | 841.2 | 100.3 % | 5.1 % | **no** |
| http | put_rate_c8 | 1 KiB | proxy | 1768.9 | 1723.2 | 102.7 % | 16.5 % | **no** |
| http | put_rate_c8 | 16 KiB | proxy | 781.7 | 954.6 | 81.9 % | 14.9 % | **no** |
| http | put_rate_c8 | 64 KiB | proxy | 912.9 | 1056.4 | 86.4 % | 13.1 % | **no** |
| tls | get_rate_c1 | 1 KiB | proxy | 1542.1 | 2970.9 | 51.9 % | 3.3 % | yes |
| tls | get_rate_c1 | 16 KiB | proxy | 1386.3 | 2421.3 | 57.3 % | 4.1 % | yes |
| tls | get_rate_c1 | 64 KiB | proxy | 1110.2 | 1708.4 | 65.0 % | 2.2 % | yes |
| tls | get_rate_c32 | 1 KiB | proxy | 4423.5 | 5834.9 | 75.8 % | 16.9 % | **no** |
| tls | get_rate_c32 | 16 KiB | proxy | 3419.6 | 4759.7 | 71.8 % | 18.5 % | **no** |
| tls | get_rate_c32 | 64 KiB | proxy | 2277.1 | 3154.9 | 72.2 % | 10.5 % | **no** |
| tls | get_rate_c8 | 1 KiB | proxy | 3770.3 | 8742.4 | 43.1 % | 17.9 % | **no** |
| tls | get_rate_c8 | 16 KiB | proxy | 3406.4 | 6465.3 | 52.7 % | 12.4 % | **no** |
| tls | get_rate_c8 | 64 KiB | proxy | 2363.7 | 3431.3 | 68.9 % | 6.9 % | **no** |
| tls | put_rate_c1 | 1 KiB | proxy | 534.5 | 745.1 | 71.7 % | 12.7 % | **no** |
| tls | put_rate_c1 | 16 KiB | proxy | 492.0 | 624.9 | 78.7 % | 13.9 % | **no** |
| tls | put_rate_c1 | 64 KiB | proxy | 381.1 | 443.8 | 85.9 % | 11.0 % | **no** |
| tls | put_rate_c32 | 1 KiB | proxy | 1252.7 | 1373.5 | 91.2 % | 6.5 % | yes |
| tls | put_rate_c32 | 16 KiB | proxy | 1072.1 | 1223.7 | 87.6 % | 9.3 % | **no** |
| tls | put_rate_c32 | 64 KiB | proxy | 821.9 | 858.9 | 95.7 % | 8.0 % | yes |
| tls | put_rate_c8 | 1 KiB | proxy | 1543.4 | 1717.7 | 89.9 % | 32.8 % | **no** |
| tls | put_rate_c8 | 16 KiB | proxy | 1121.9 | 1404.8 | 79.9 % | 14.3 % | **no** |
| tls | put_rate_c8 | 64 KiB | proxy | 1071.5 | 1222.0 | 87.7 % | 15.1 % | **no** |

## Upload write paths — single request against the multipart producer

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | upload | 16 MiB | proxy | 145.4 | 156.4 | 92.9 % | 5.1 % | yes |
| http | upload | 16 MiB | proxy-streaming | 163.7 | 156.4 | 104.6 % | 3.9 % | yes |
| http | upload | 24 MiB | proxy | 145.1 | — | — | 6.5 % | yes |
| http | upload | 24 MiB | proxy-streaming | 175.5 | — | — | 4.9 % | yes |
| http | upload | 64 MiB | proxy | 184.0 | — | — | 7.9 % | yes |
| http | upload | 64 MiB | proxy-streaming | 190.1 | — | — | 3.0 % | yes |
| http | upload | 256 MiB | proxy | 200.3 | — | — | 1.3 % | yes |
| http | upload | 256 MiB | proxy-streaming | 185.5 | — | — | 3.4 % | yes |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 549.9 | ns/op | 15.6 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 669394 | ns/op | 3.6 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3890539 | ns/op | 2.1 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 935.6 | ns/op | 6.8 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 21508 | ns/op | 2.0 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 104388 | ns/op | 3.3 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | codec_decrypt | 64 KiB | 2199 | MiB/s | 24.1 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 1 MiB | 3523 | MiB/s | 19.0 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 12 MiB | 4502 | MiB/s | 2.6 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 128 MiB | 4312 | MiB/s | 1.1 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_encrypt | 64 KiB | 1716 | MiB/s | 60.8 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 1 MiB | 3542 | MiB/s | 4.4 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 12 MiB | 4510 | MiB/s | 1.0 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 128 MiB | 4491 | MiB/s | 2.5 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | crc32c | 64 KiB | 10135 | MiB/s | 0.3 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 1 MiB | 9040 | MiB/s | 9.0 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 12 MiB | 11683 | MiB/s | 1.3 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 128 MiB | 11602 | MiB/s | 0.2 % | 7 | plaintext checksum the trailer carries |
| in-process | gcm_seg_decrypt | 64 KiB | 8152 | MiB/s | 26.8 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 1 MiB | 7467 | MiB/s | 5.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 12 MiB | 8910 | MiB/s | 0.9 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 128 MiB | 8906 | MiB/s | 0.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 64 KiB | 7692 | MiB/s | 1.3 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 1 MiB | 7407 | MiB/s | 4.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 12 MiB | 8234 | MiB/s | 1.7 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 128 MiB | 8353 | MiB/s | 0.6 % | 7 | per-segment AES-GCM only, no trailer and no checksum |

## Proxy resident memory

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| proxy | rss_cold | — | 20824064 | bytes | 0.0 % | 1 | resident memory before this run touched the proxy — recorded, not asserted |
| proxy | rss_cold_load_peak | — | 91475968 | bytes | 0.0 % | 1 | peak during the first (warm-up) load, i.e. what reaching the settled level costs — recorded, not asserted |
| proxy | rss_idle | — | 105373696 | bytes | 6.3 % | 7 | process_resident_memory_bytes before each repetition's load; after the warm-up this is the settled level, not a cold process — recorded, not asserted |
| proxy | rss_limit | — | 536870912 | bytes | 0.0 % | 1 | container memory limit from docker-compose.demo.yml — recorded, not asserted |
| proxy | rss_peak | — | 107425792 | bytes | 1.7 % | 7 | maximum of a 250ms sample while 2×128 MiB PUT+GET plus 1 MiB PUT+GET ran — recorded, not asserted |
| proxy | rss_peak_minus_idle | — | 2359296 | bytes | 111.6 % | 7 | what the load itself costs; the bound of ADR 0020 D14 applies to this figure — recorded, not asserted |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
