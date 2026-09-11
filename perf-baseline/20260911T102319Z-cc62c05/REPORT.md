# Performance baseline — post-v2-wave5-drained

Run `20260911T102319Z-cc62c05`, schema 1. 2026-09-11T10:23:19Z → 2026-09-11T10:30:29Z (430 s), 7 repetitions per point.

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
| Load average before | 3.36 / 4.45 / 3.87 |
| Load average after | 7.39 / 6.03 / 4.77 |

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
| http | download | 1 KiB | proxy | 1.3 | 2.3 | 56.4 % | 20.8 % | **no** |
| http | download | 64 KiB | proxy | 64.2 | 94.6 | 67.8 % | 17.4 % | **no** |
| http | download | 256 KiB | proxy | 124.1 | 179.4 | 69.2 % | 4.5 % | yes |
| http | download | 1 MiB | proxy | 194.5 | 232.9 | 83.5 % | 4.3 % | yes |
| http | download | 4 MiB | proxy | 235.4 | 244.4 | 96.3 % | 2.9 % | yes |
| http | download | 5 MiB | proxy | 235.1 | 246.4 | 95.4 % | 3.8 % | yes |
| http | download | 8 MiB | proxy | 242.8 | 246.4 | 98.5 % | 3.2 % | **no** |
| http | download | 32 MiB | proxy | 252.9 | 254.3 | 99.5 % | 3.9 % | yes |
| http | download | 128 MiB | proxy | 250.3 | 247.3 | 101.2 % | 3.4 % | yes |
| http | upload | 1 KiB | proxy | 0.4 | 0.8 | 48.1 % | 32.2 % | **no** |
| http | upload | 64 KiB | proxy | 35.7 | 47.2 | 75.6 % | 17.0 % | **no** |
| http | upload | 256 KiB | proxy | 79.8 | 68.0 | 117.5 % | 18.1 % | **no** |
| http | upload | 1 MiB | proxy | 127.1 | 131.8 | 96.4 % | 10.3 % | **no** |
| http | upload | 4 MiB | proxy | 155.6 | 142.8 | 109.0 % | 13.5 % | **no** |
| http | upload | 5 MiB | proxy | 165.5 | 145.6 | 113.7 % | 5.9 % | yes |
| http | upload | 8 MiB | proxy | 152.7 | 149.4 | 102.2 % | 9.4 % | **no** |
| http | upload | 32 MiB | proxy | 183.5 | 209.2 | 87.7 % | 1.4 % | **no** |
| http | upload | 128 MiB | proxy | 224.0 | 248.4 | 90.1 % | 5.0 % | yes |
| tls | download | 1 KiB | proxy | 1.2 | 2.2 | 52.7 % | 12.0 % | **no** |
| tls | download | 64 KiB | proxy | 54.7 | 96.1 | 57.0 % | 15.5 % | **no** |
| tls | download | 256 KiB | proxy | 115.8 | 184.6 | 62.7 % | 5.5 % | yes |
| tls | download | 1 MiB | proxy | 176.9 | 226.7 | 78.0 % | 4.5 % | yes |
| tls | download | 4 MiB | proxy | 224.4 | 243.4 | 92.2 % | 10.4 % | **no** |
| tls | download | 5 MiB | proxy | 233.1 | 238.3 | 97.8 % | 4.0 % | yes |
| tls | download | 8 MiB | proxy | 232.5 | 235.7 | 98.7 % | 10.5 % | **no** |
| tls | download | 32 MiB | proxy | 243.6 | 227.7 | 107.0 % | 3.9 % | yes |
| tls | download | 128 MiB | proxy | 221.0 | 220.2 | 100.4 % | 2.3 % | yes |
| tls | upload | 1 KiB | proxy | 0.3 | 0.3 | 95.5 % | 52.7 % | **no** |
| tls | upload | 64 KiB | proxy | 15.5 | 23.4 | 66.1 % | 69.7 % | **no** |
| tls | upload | 256 KiB | proxy | 78.2 | 60.5 | 129.3 % | 23.2 % | **no** |
| tls | upload | 1 MiB | proxy | 148.6 | 127.0 | 117.0 % | 11.6 % | **no** |
| tls | upload | 4 MiB | proxy | 166.5 | 146.8 | 113.4 % | 9.4 % | yes |
| tls | upload | 5 MiB | proxy | 167.8 | 137.8 | 121.7 % | 4.5 % | yes |
| tls | upload | 8 MiB | proxy | 162.1 | 143.2 | 113.2 % | 7.3 % | yes |
| tls | upload | 32 MiB | proxy | 177.9 | 194.4 | 91.5 % | 3.7 % | yes |
| tls | upload | 128 MiB | proxy | 204.4 | 199.6 | 102.4 % | 2.5 % | yes |

## Ranged read — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | range_mid_aligned | 64 KiB | proxy | 49.1 | 70.0 | 70.1 % | 6.9 % | yes |
| http | range_mid_aligned | 1 MiB | proxy | 202.6 | 209.5 | 96.7 % | 13.2 % | **no** |
| http | range_mid_aligned | 8 MiB | proxy | 236.7 | 243.4 | 97.2 % | 5.8 % | yes |
| http | range_mid_unaligned | 64 KiB | proxy | 56.7 | 75.4 | 75.2 % | 11.0 % | **no** |
| http | range_mid_unaligned | 1 MiB | proxy | 201.1 | 215.8 | 93.2 % | 15.2 % | **no** |
| http | range_mid_unaligned | 8 MiB | proxy | 247.4 | 240.3 | 102.9 % | 2.0 % | yes |
| http | range_start | 64 KiB | proxy | 39.9 | 56.8 | 70.2 % | 7.3 % | yes |
| http | range_start | 1 MiB | proxy | 211.0 | 221.2 | 95.4 % | 3.4 % | yes |
| http | range_start | 8 MiB | proxy | 250.3 | 250.0 | 100.1 % | 2.9 % | yes |
| http | range_tail | 64 KiB | proxy | 50.5 | 70.2 | 71.9 % | 6.5 % | **no** |
| http | range_tail | 1 MiB | proxy | 207.2 | 207.6 | 99.8 % | 4.7 % | yes |
| http | range_tail | 8 MiB | proxy | 243.5 | 245.2 | 99.3 % | 1.3 % | yes |
| tls | range_mid_aligned | 64 KiB | proxy | 47.7 | 66.5 | 71.7 % | 6.3 % | yes |
| tls | range_mid_aligned | 1 MiB | proxy | 206.1 | 224.1 | 92.0 % | 5.3 % | yes |
| tls | range_mid_aligned | 8 MiB | proxy | 246.4 | 254.3 | 96.9 % | 4.8 % | yes |
| tls | range_mid_unaligned | 64 KiB | proxy | 54.8 | 75.2 | 73.0 % | 8.7 % | **no** |
| tls | range_mid_unaligned | 1 MiB | proxy | 206.6 | 222.9 | 92.7 % | 5.0 % | yes |
| tls | range_mid_unaligned | 8 MiB | proxy | 254.5 | 255.2 | 99.7 % | 2.9 % | yes |
| tls | range_start | 64 KiB | proxy | 40.8 | 57.7 | 70.8 % | 8.6 % | yes |
| tls | range_start | 1 MiB | proxy | 208.2 | 224.0 | 93.0 % | 4.6 % | yes |
| tls | range_start | 8 MiB | proxy | 256.7 | 268.3 | 95.7 % | 5.8 % | yes |
| tls | range_tail | 64 KiB | proxy | 48.6 | 72.0 | 67.5 % | 9.7 % | yes |
| tls | range_tail | 1 MiB | proxy | 199.7 | 226.9 | 88.0 % | 14.2 % | **no** |
| tls | range_tail | 8 MiB | proxy | 254.4 | 258.0 | 98.6 % | 3.0 % | yes |

## Small objects — request rate

| Transport | Operation | Size | Subject | ops/s | direct (ops/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | get_rate_c1 | 1 KiB | proxy | 1573.9 | 2876.0 | 54.7 % | 2.6 % | yes |
| http | get_rate_c1 | 16 KiB | proxy | 1425.2 | 2489.3 | 57.3 % | 2.1 % | yes |
| http | get_rate_c1 | 64 KiB | proxy | 1089.3 | 1687.1 | 64.6 % | 5.2 % | yes |
| http | get_rate_c32 | 1 KiB | proxy | 3928.7 | 7436.8 | 52.8 % | 9.5 % | **no** |
| http | get_rate_c32 | 16 KiB | proxy | 3290.1 | 4486.5 | 73.3 % | 13.7 % | **no** |
| http | get_rate_c32 | 64 KiB | proxy | 2148.7 | 3004.2 | 71.5 % | 14.9 % | **no** |
| http | get_rate_c8 | 1 KiB | proxy | 4233.9 | 8714.5 | 48.6 % | 10.6 % | **no** |
| http | get_rate_c8 | 16 KiB | proxy | 3652.0 | 7214.8 | 50.6 % | 13.2 % | **no** |
| http | get_rate_c8 | 64 KiB | proxy | 2426.0 | 2855.7 | 85.0 % | 8.5 % | **no** |
| http | put_rate_c1 | 1 KiB | proxy | 475.1 | 582.5 | 81.6 % | 13.6 % | **no** |
| http | put_rate_c1 | 16 KiB | proxy | 471.1 | 611.6 | 77.0 % | 6.9 % | **no** |
| http | put_rate_c1 | 64 KiB | proxy | 359.9 | 425.2 | 84.6 % | 3.5 % | yes |
| http | put_rate_c32 | 1 KiB | proxy | 1192.6 | 1339.8 | 89.0 % | 8.2 % | yes |
| http | put_rate_c32 | 16 KiB | proxy | 1117.4 | 1302.7 | 85.8 % | 10.6 % | **no** |
| http | put_rate_c32 | 64 KiB | proxy | 809.3 | 841.7 | 96.2 % | 6.5 % | **no** |
| http | put_rate_c8 | 1 KiB | proxy | 1496.1 | 1912.3 | 78.2 % | 29.7 % | **no** |
| http | put_rate_c8 | 16 KiB | proxy | 1044.5 | 985.4 | 106.0 % | 12.3 % | **no** |
| http | put_rate_c8 | 64 KiB | proxy | 946.6 | 1088.3 | 87.0 % | 12.2 % | **no** |
| tls | get_rate_c1 | 1 KiB | proxy | 1570.0 | 2953.5 | 53.2 % | 2.7 % | yes |
| tls | get_rate_c1 | 16 KiB | proxy | 1403.7 | 2484.0 | 56.5 % | 1.6 % | yes |
| tls | get_rate_c1 | 64 KiB | proxy | 1040.5 | 1717.7 | 60.6 % | 2.2 % | yes |
| tls | get_rate_c32 | 1 KiB | proxy | 4391.7 | 7487.7 | 58.7 % | 14.0 % | **no** |
| tls | get_rate_c32 | 16 KiB | proxy | 2717.1 | 6441.9 | 42.2 % | 21.9 % | **no** |
| tls | get_rate_c32 | 64 KiB | proxy | 2487.4 | 3083.4 | 80.7 % | 12.4 % | **no** |
| tls | get_rate_c8 | 1 KiB | proxy | 4314.1 | 7392.3 | 58.4 % | 4.0 % | **no** |
| tls | get_rate_c8 | 16 KiB | proxy | 3551.1 | 6847.6 | 51.9 % | 12.3 % | **no** |
| tls | get_rate_c8 | 64 KiB | proxy | 2269.0 | 3207.7 | 70.7 % | 8.9 % | yes |
| tls | put_rate_c1 | 1 KiB | proxy | 413.0 | 506.2 | 81.6 % | 17.8 % | **no** |
| tls | put_rate_c1 | 16 KiB | proxy | 456.8 | 511.0 | 89.4 % | 11.8 % | **no** |
| tls | put_rate_c1 | 64 KiB | proxy | 403.7 | 510.1 | 79.1 % | 11.2 % | **no** |
| tls | put_rate_c32 | 1 KiB | proxy | 1291.1 | 1387.8 | 93.0 % | 7.5 % | yes |
| tls | put_rate_c32 | 16 KiB | proxy | 1016.4 | 1249.8 | 81.3 % | 7.8 % | yes |
| tls | put_rate_c32 | 64 KiB | proxy | 810.3 | 821.7 | 98.6 % | 3.5 % | yes |
| tls | put_rate_c8 | 1 KiB | proxy | 1770.0 | 2359.6 | 75.0 % | 13.9 % | **no** |
| tls | put_rate_c8 | 16 KiB | proxy | 1106.3 | 1252.7 | 88.3 % | 20.7 % | **no** |
| tls | put_rate_c8 | 64 KiB | proxy | 1093.1 | 1163.3 | 94.0 % | 14.6 % | **no** |

## Upload write paths — single request against the multipart producer

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | upload | 16 MiB | proxy | 144.5 | 158.4 | 91.2 % | 9.2 % | yes |
| http | upload | 16 MiB | proxy-streaming | 155.9 | 158.4 | 98.5 % | 7.4 % | yes |
| http | upload | 24 MiB | proxy | 150.2 | — | — | 5.5 % | yes |
| http | upload | 24 MiB | proxy-streaming | 170.0 | — | — | 5.2 % | yes |
| http | upload | 64 MiB | proxy | 187.9 | — | — | 1.4 % | yes |
| http | upload | 64 MiB | proxy-streaming | 176.9 | — | — | 8.3 % | yes |
| http | upload | 256 MiB | proxy | 189.7 | — | — | 0.5 % | yes |
| http | upload | 256 MiB | proxy-streaming | 174.5 | — | — | 3.3 % | yes |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 521.8 | ns/op | 9.8 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 646425 | ns/op | 0.4 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3869768 | ns/op | 1.0 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 913.6 | ns/op | 5.6 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 20738 | ns/op | 1.6 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 101591 | ns/op | 3.0 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | codec_decrypt | 64 KiB | 2381 | MiB/s | 16.9 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 1 MiB | 4122 | MiB/s | 15.3 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 12 MiB | 4206 | MiB/s | 2.6 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 128 MiB | 4331 | MiB/s | 1.4 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_encrypt | 64 KiB | 2636 | MiB/s | 72.7 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 1 MiB | 4167 | MiB/s | 1.0 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 12 MiB | 4137 | MiB/s | 1.6 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 128 MiB | 4201 | MiB/s | 1.2 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | crc32c | 64 KiB | 10715 | MiB/s | 0.8 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 1 MiB | 10767 | MiB/s | 0.2 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 12 MiB | 10567 | MiB/s | 1.3 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 128 MiB | 10867 | MiB/s | 1.5 % | 7 | plaintext checksum the trailer carries |
| in-process | gcm_seg_decrypt | 64 KiB | 8721 | MiB/s | 0.7 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 1 MiB | 8655 | MiB/s | 0.1 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 12 MiB | 8708 | MiB/s | 2.8 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 128 MiB | 8709 | MiB/s | 0.3 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 64 KiB | 8153 | MiB/s | 0.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 1 MiB | 8119 | MiB/s | 0.6 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 12 MiB | 8091 | MiB/s | 1.2 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 128 MiB | 8103 | MiB/s | 0.6 % | 7 | per-segment AES-GCM only, no trailer and no checksum |

## Proxy resident memory

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| proxy | rss_cold | — | 22667264 | bytes | 0.0 % | 1 | resident memory before this run touched the proxy — recorded, not asserted |
| proxy | rss_cold_load_peak | — | 105484288 | bytes | 0.0 % | 1 | peak during the first (warm-up) load, i.e. what reaching the settled level costs — recorded, not asserted |
| proxy | rss_idle | — | 108027904 | bytes | 4.0 % | 7 | process_resident_memory_bytes before each repetition's load; after the warm-up this is the settled level, not a cold process — recorded, not asserted |
| proxy | rss_limit | — | 536870912 | bytes | 0.0 % | 1 | container memory limit from docker-compose.demo.yml — recorded, not asserted |
| proxy | rss_peak | — | 109248512 | bytes | 1.3 % | 7 | maximum of a 250ms sample while 2×128 MiB PUT+GET plus 1 MiB PUT+GET ran — recorded, not asserted |
| proxy | rss_peak_minus_idle | — | 1179648 | bytes | 140.4 % | 7 | what the load itself costs; the bound of ADR 0020 D14 applies to this figure — recorded, not asserted |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
