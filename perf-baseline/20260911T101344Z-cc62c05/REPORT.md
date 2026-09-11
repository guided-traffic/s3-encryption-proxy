# Performance baseline — post-v2-wave5

Run `20260911T101344Z-cc62c05`, schema 1. 2026-09-11T10:13:44Z → 2026-09-11T10:20:24Z (400 s), 7 repetitions per point.

Commit `cc62c055a8035918a9c84102b5fc7a443bafcffe` on `feat/major-v5`.

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
| Load average before | 2.89 / 3.80 / 3.03 |
| Load average after | 7.09 / 5.48 / 4.05 |

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
| http | download | 1 KiB | proxy | 1.2 | 1.9 | 64.8 % | 19.6 % | **no** |
| http | download | 64 KiB | proxy | 64.7 | 94.9 | 68.1 % | 9.4 % | yes |
| http | download | 256 KiB | proxy | 125.2 | 175.5 | 71.4 % | 6.9 % | yes |
| http | download | 1 MiB | proxy | 194.8 | 235.2 | 82.8 % | 1.9 % | yes |
| http | download | 4 MiB | proxy | 243.7 | 242.4 | 100.5 % | 3.0 % | yes |
| http | download | 5 MiB | proxy | 246.7 | 249.5 | 98.9 % | 3.2 % | yes |
| http | download | 8 MiB | proxy | 257.2 | 253.5 | 101.5 % | 5.1 % | yes |
| http | download | 32 MiB | proxy | 264.6 | 252.8 | 104.6 % | 5.0 % | yes |
| http | download | 128 MiB | proxy | 259.8 | 254.9 | 101.9 % | 2.0 % | yes |
| http | upload | 1 KiB | proxy | 0.7 | 1.0 | 71.1 % | 34.1 % | **no** |
| http | upload | 64 KiB | proxy | 33.6 | 45.2 | 74.3 % | 17.1 % | **no** |
| http | upload | 256 KiB | proxy | 79.0 | 87.2 | 90.6 % | 18.6 % | **no** |
| http | upload | 1 MiB | proxy | 131.1 | 134.5 | 97.5 % | 7.3 % | yes |
| http | upload | 4 MiB | proxy | 176.4 | 156.9 | 112.4 % | 7.7 % | yes |
| http | upload | 5 MiB | proxy | 176.8 | 160.6 | 110.0 % | 3.7 % | yes |
| http | upload | 8 MiB | proxy | 169.1 | 157.3 | 107.5 % | 13.6 % | **no** |
| http | upload | 32 MiB | proxy | 201.8 | 218.9 | 92.2 % | 6.4 % | yes |
| http | upload | 128 MiB | proxy | 249.5 | 258.7 | 96.4 % | 3.5 % | yes |
| tls | download | 1 KiB | proxy | 1.6 | 3.0 | 52.7 % | 7.3 % | yes |
| tls | download | 64 KiB | proxy | 62.7 | 108.0 | 58.1 % | 6.9 % | yes |
| tls | download | 256 KiB | proxy | 117.1 | 182.6 | 64.1 % | 8.8 % | yes |
| tls | download | 1 MiB | proxy | 192.9 | 230.4 | 83.8 % | 4.4 % | yes |
| tls | download | 4 MiB | proxy | 242.4 | 240.1 | 101.0 % | 4.1 % | yes |
| tls | download | 5 MiB | proxy | 244.9 | 249.8 | 98.0 % | 3.3 % | yes |
| tls | download | 8 MiB | proxy | 244.1 | 241.4 | 101.1 % | 4.8 % | yes |
| tls | download | 32 MiB | proxy | 258.3 | 254.4 | 101.5 % | 5.1 % | yes |
| tls | download | 128 MiB | proxy | 255.6 | 245.5 | 104.1 % | 3.1 % | yes |
| tls | upload | 1 KiB | proxy | 0.9 | 1.2 | 75.6 % | 13.3 % | **no** |
| tls | upload | 64 KiB | proxy | 43.1 | 54.9 | 78.4 % | 9.8 % | yes |
| tls | upload | 256 KiB | proxy | 99.6 | 97.8 | 101.9 % | 10.9 % | **no** |
| tls | upload | 1 MiB | proxy | 134.8 | 136.6 | 98.7 % | 7.2 % | yes |
| tls | upload | 4 MiB | proxy | 186.8 | 158.4 | 117.9 % | 4.2 % | yes |
| tls | upload | 5 MiB | proxy | 181.3 | 165.1 | 109.8 % | 6.4 % | yes |
| tls | upload | 8 MiB | proxy | 198.5 | 160.7 | 123.5 % | 6.7 % | **no** |
| tls | upload | 32 MiB | proxy | 204.9 | 218.6 | 93.7 % | 5.7 % | yes |
| tls | upload | 128 MiB | proxy | 245.0 | 255.3 | 96.0 % | 4.0 % | yes |

## Ranged read — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | range_mid_aligned | 64 KiB | proxy | 48.8 | 75.0 | 65.1 % | 8.0 % | yes |
| http | range_mid_aligned | 1 MiB | proxy | 157.6 | 221.1 | 71.3 % | 4.3 % | yes |
| http | range_mid_aligned | 8 MiB | proxy | 230.2 | 248.2 | 92.8 % | 6.5 % | yes |
| http | range_mid_unaligned | 64 KiB | proxy | 54.9 | 78.9 | 69.6 % | 7.5 % | **no** |
| http | range_mid_unaligned | 1 MiB | proxy | 155.0 | 209.3 | 74.0 % | 4.0 % | yes |
| http | range_mid_unaligned | 8 MiB | proxy | 229.0 | 246.7 | 92.8 % | 2.2 % | yes |
| http | range_start | 64 KiB | proxy | 37.9 | 56.4 | 67.2 % | 4.5 % | **no** |
| http | range_start | 1 MiB | proxy | 202.2 | 224.0 | 90.3 % | 2.3 % | yes |
| http | range_start | 8 MiB | proxy | 236.4 | 249.2 | 94.9 % | 3.6 % | yes |
| http | range_tail | 64 KiB | proxy | 54.1 | 76.3 | 70.8 % | 4.2 % | **no** |
| http | range_tail | 1 MiB | proxy | 154.3 | 215.5 | 71.6 % | 3.2 % | yes |
| http | range_tail | 8 MiB | proxy | 236.1 | 246.6 | 95.7 % | 4.5 % | yes |
| tls | range_mid_aligned | 64 KiB | proxy | 55.9 | 76.8 | 72.7 % | 9.1 % | yes |
| tls | range_mid_aligned | 1 MiB | proxy | 144.5 | 214.2 | 67.4 % | 9.1 % | yes |
| tls | range_mid_aligned | 8 MiB | proxy | 238.6 | 245.9 | 97.0 % | 4.6 % | yes |
| tls | range_mid_unaligned | 64 KiB | proxy | 57.8 | 78.3 | 73.9 % | 8.3 % | **no** |
| tls | range_mid_unaligned | 1 MiB | proxy | 159.0 | 228.3 | 69.7 % | 9.2 % | yes |
| tls | range_mid_unaligned | 8 MiB | proxy | 237.8 | 245.2 | 97.0 % | 3.1 % | yes |
| tls | range_start | 64 KiB | proxy | 44.0 | 64.1 | 68.6 % | 10.8 % | **no** |
| tls | range_start | 1 MiB | proxy | 197.2 | 228.8 | 86.2 % | 6.4 % | **no** |
| tls | range_start | 8 MiB | proxy | 257.0 | 253.4 | 101.4 % | 5.1 % | yes |
| tls | range_tail | 64 KiB | proxy | 55.3 | 76.7 | 72.1 % | 9.1 % | **no** |
| tls | range_tail | 1 MiB | proxy | 157.5 | 231.4 | 68.1 % | 7.8 % | yes |
| tls | range_tail | 8 MiB | proxy | 233.7 | 242.0 | 96.6 % | 3.2 % | yes |

## Small objects — request rate

| Transport | Operation | Size | Subject | ops/s | direct (ops/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | get_rate_c1 | 1 KiB | proxy | 1563.2 | 2939.3 | 53.2 % | 3.0 % | yes |
| http | get_rate_c1 | 16 KiB | proxy | 1437.9 | 2486.9 | 57.8 % | 2.3 % | yes |
| http | get_rate_c1 | 64 KiB | proxy | 1134.7 | 1717.4 | 66.1 % | 2.7 % | yes |
| http | get_rate_c32 | 1 KiB | proxy | 3391.9 | 8102.1 | 41.9 % | 13.8 % | **no** |
| http | get_rate_c32 | 16 KiB | proxy | 3317.8 | 4857.8 | 68.3 % | 9.3 % | **no** |
| http | get_rate_c32 | 64 KiB | proxy | 2256.1 | 3161.4 | 71.4 % | 12.3 % | **no** |
| http | get_rate_c8 | 1 KiB | proxy | 4006.4 | 10500.9 | 38.2 % | 9.4 % | **no** |
| http | get_rate_c8 | 16 KiB | proxy | 3979.7 | 7196.1 | 55.3 % | 12.0 % | **no** |
| http | get_rate_c8 | 64 KiB | proxy | 2532.2 | 2936.4 | 86.2 % | 7.0 % | yes |
| http | put_rate_c1 | 1 KiB | proxy | 621.0 | 804.7 | 77.2 % | 6.9 % | yes |
| http | put_rate_c1 | 16 KiB | proxy | 500.6 | 637.4 | 78.5 % | 4.9 % | yes |
| http | put_rate_c1 | 64 KiB | proxy | 488.2 | 621.6 | 78.5 % | 8.8 % | yes |
| http | put_rate_c32 | 1 KiB | proxy | 1305.1 | 1392.0 | 93.8 % | 6.5 % | yes |
| http | put_rate_c32 | 16 KiB | proxy | 1114.8 | 1198.5 | 93.0 % | 11.9 % | **no** |
| http | put_rate_c32 | 64 KiB | proxy | 786.3 | 840.5 | 93.5 % | 4.9 % | **no** |
| http | put_rate_c8 | 1 KiB | proxy | 1421.0 | 1549.8 | 91.7 % | 12.7 % | **no** |
| http | put_rate_c8 | 16 KiB | proxy | 1120.9 | 1081.8 | 103.6 % | 21.7 % | **no** |
| http | put_rate_c8 | 64 KiB | proxy | 1065.1 | 1087.2 | 98.0 % | 7.4 % | yes |
| tls | get_rate_c1 | 1 KiB | proxy | 1554.2 | 2983.8 | 52.1 % | 4.8 % | **no** |
| tls | get_rate_c1 | 16 KiB | proxy | 1445.1 | 2460.2 | 58.7 % | 2.2 % | yes |
| tls | get_rate_c1 | 64 KiB | proxy | 1112.1 | 1723.8 | 64.5 % | 5.2 % | yes |
| tls | get_rate_c32 | 1 KiB | proxy | 3888.2 | 4315.1 | 90.1 % | 19.7 % | **no** |
| tls | get_rate_c32 | 16 KiB | proxy | 2965.1 | 5817.4 | 51.0 % | 15.3 % | **no** |
| tls | get_rate_c32 | 64 KiB | proxy | 2615.3 | 3294.2 | 79.4 % | 8.5 % | yes |
| tls | get_rate_c8 | 1 KiB | proxy | 4232.8 | 7065.3 | 59.9 % | 7.4 % | **no** |
| tls | get_rate_c8 | 16 KiB | proxy | 4004.4 | 7181.1 | 55.8 % | 11.9 % | **no** |
| tls | get_rate_c8 | 64 KiB | proxy | 2288.2 | 3257.1 | 70.3 % | 8.1 % | **no** |
| tls | put_rate_c1 | 1 KiB | proxy | 574.9 | 763.5 | 75.3 % | 14.5 % | **no** |
| tls | put_rate_c1 | 16 KiB | proxy | 541.8 | 746.8 | 72.5 % | 7.1 % | **no** |
| tls | put_rate_c1 | 64 KiB | proxy | 436.5 | 535.4 | 81.5 % | 14.8 % | **no** |
| tls | put_rate_c32 | 1 KiB | proxy | 1141.6 | 1539.8 | 74.1 % | 10.5 % | **no** |
| tls | put_rate_c32 | 16 KiB | proxy | 1125.7 | 1188.3 | 94.7 % | 7.1 % | yes |
| tls | put_rate_c32 | 64 KiB | proxy | 864.6 | 885.1 | 97.7 % | 7.7 % | yes |
| tls | put_rate_c8 | 1 KiB | proxy | 1835.5 | 2283.2 | 80.4 % | 21.9 % | **no** |
| tls | put_rate_c8 | 16 KiB | proxy | 1676.1 | 2060.1 | 81.4 % | 21.5 % | **no** |
| tls | put_rate_c8 | 64 KiB | proxy | 1116.0 | 1233.9 | 90.4 % | 12.0 % | **no** |

## Upload write paths — single request against the multipart producer

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | upload | 16 MiB | proxy | 151.2 | 159.5 | 94.8 % | 6.8 % | **no** |
| http | upload | 16 MiB | proxy-streaming | 166.3 | 159.5 | 104.3 % | 8.7 % | **no** |
| http | upload | 24 MiB | proxy | 154.5 | — | — | 1.9 % | yes |
| http | upload | 24 MiB | proxy-streaming | 175.7 | — | — | 2.5 % | yes |
| http | upload | 64 MiB | proxy | 193.3 | — | — | 1.9 % | yes |
| http | upload | 64 MiB | proxy-streaming | 183.7 | — | — | 4.0 % | yes |
| http | upload | 256 MiB | proxy | 203.0 | — | — | 1.1 % | yes |
| http | upload | 256 MiB | proxy-streaming | 182.5 | — | — | 3.3 % | yes |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 501.8 | ns/op | 8.0 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 641795 | ns/op | 1.0 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3834008 | ns/op | 1.0 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 883.3 | ns/op | 4.5 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 20423 | ns/op | 1.3 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 99488 | ns/op | 1.6 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | codec_decrypt | 64 KiB | 2347 | MiB/s | 13.1 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 1 MiB | 3745 | MiB/s | 15.1 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 12 MiB | 4474 | MiB/s | 1.1 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 128 MiB | 4354 | MiB/s | 1.7 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_encrypt | 64 KiB | 2119 | MiB/s | 68.3 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 1 MiB | 3982 | MiB/s | 1.1 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 12 MiB | 4439 | MiB/s | 1.3 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 128 MiB | 4449 | MiB/s | 0.5 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | crc32c | 64 KiB | 9375 | MiB/s | 8.7 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 1 MiB | 9848 | MiB/s | 4.6 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 12 MiB | 11367 | MiB/s | 1.4 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 128 MiB | 11550 | MiB/s | 0.4 % | 7 | plaintext checksum the trailer carries |
| in-process | gcm_seg_decrypt | 64 KiB | 6757 | MiB/s | 4.2 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 1 MiB | 7569 | MiB/s | 3.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 12 MiB | 8890 | MiB/s | 1.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 128 MiB | 8895 | MiB/s | 0.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 64 KiB | 6551 | MiB/s | 7.8 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 1 MiB | 7203 | MiB/s | 3.2 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 12 MiB | 8209 | MiB/s | 2.0 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 128 MiB | 8297 | MiB/s | 0.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |

## Proxy resident memory

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| proxy | rss_cold | — | 22712320 | bytes | 0.0 % | 1 | resident memory before this run touched the proxy — recorded, not asserted |
| proxy | rss_cold_load_peak | — | 106328064 | bytes | 0.0 % | 1 | peak during the first (warm-up) load, i.e. what reaching the settled level costs — recorded, not asserted |
| proxy | rss_idle | — | 93175808 | bytes | 7.9 % | 7 | process_resident_memory_bytes before each repetition's load; after the warm-up this is the settled level, not a cold process — recorded, not asserted |
| proxy | rss_limit | — | 536870912 | bytes | 0.0 % | 1 | container memory limit from docker-compose.demo.yml — recorded, not asserted |
| proxy | rss_peak | — | 108724224 | bytes | 1.4 % | 7 | maximum of a 250ms sample while 2×128 MiB PUT+GET plus 1 MiB PUT+GET ran — recorded, not asserted |
| proxy | rss_peak_minus_idle | — | 14315520 | bytes | 74.7 % | 7 | what the load itself costs; the bound of ADR 0020 D14 applies to this figure — recorded, not asserted |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
