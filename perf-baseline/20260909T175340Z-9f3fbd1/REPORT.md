# Performance baseline — pre-v2

Run `20260909T175340Z-9f3fbd1`, schema 1. 2026-09-09T17:53:40Z → 2026-09-09T18:01:14Z (454 s), 7 repetitions per point.

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
| Load average before | 4.49 / 7.13 / 5.83 |
| Load average after | 8.44 / 8.51 / 7.12 |

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
| memory | ok | — |
| profiles | ok | — |
| rangeread | ok | — |
| smallobject | ok | — |
| throughput | ok | — |
| unwrap | ok | — |

## Throughput — proxy against direct backend

| Transport | Operation | Size | Proxy (MiB/s) | Direct (MiB/s) | Ratio | Proxy RSD | Stable |
|---|---|---|---:|---:|---:|---:|:--:|
| http | download | 1 KiB | 1.3 | 2.3 | 57.9 % | 20.9 % | **no** |
| http | download | 64 KiB | 64.7 | 91.5 | 70.7 % | 16.6 % | **no** |
| http | download | 256 KiB | 127.0 | 178.5 | 71.2 % | 8.0 % | yes |
| http | download | 1 MiB | 170.4 | 221.4 | 76.9 % | 9.8 % | yes |
| http | download | 4 MiB | 212.4 | 242.8 | 87.5 % | 8.9 % | yes |
| http | download | 5 MiB | 244.0 | 248.8 | 98.1 % | 6.1 % | yes |
| http | download | 8 MiB | 253.2 | 250.8 | 100.9 % | 5.0 % | yes |
| http | download | 32 MiB | 269.1 | 261.3 | 103.0 % | 2.9 % | yes |
| http | download | 128 MiB | 256.3 | 249.1 | 102.9 % | 4.2 % | yes |
| http | upload | 1 KiB | 0.7 | 0.9 | 85.9 % | 21.6 % | **no** |
| http | upload | 64 KiB | 32.5 | 46.8 | 69.5 % | 11.6 % | **no** |
| http | upload | 256 KiB | 59.8 | 88.2 | 67.8 % | 5.0 % | yes |
| http | upload | 1 MiB | 91.2 | 128.7 | 70.9 % | 13.7 % | **no** |
| http | upload | 4 MiB | 113.6 | 157.4 | 72.2 % | 5.6 % | yes |
| http | upload | 5 MiB | 88.1 | 148.6 | 59.3 % | 4.6 % | yes |
| http | upload | 8 MiB | 92.0 | 152.7 | 60.2 % | 4.4 % | yes |
| http | upload | 32 MiB | 121.2 | 214.8 | 56.4 % | 4.7 % | yes |
| http | upload | 128 MiB | 148.4 | 246.9 | 60.1 % | 14.3 % | **no** |
| tls | download | 1 KiB | 1.7 | 2.9 | 59.6 % | 11.1 % | **no** |
| tls | download | 64 KiB | 71.4 | 105.2 | 67.9 % | 11.5 % | **no** |
| tls | download | 256 KiB | 136.7 | 191.6 | 71.4 % | 10.0 % | yes |
| tls | download | 1 MiB | 191.4 | 227.1 | 84.3 % | 4.5 % | yes |
| tls | download | 4 MiB | 206.0 | 243.5 | 84.6 % | 3.8 % | yes |
| tls | download | 5 MiB | 249.9 | 249.2 | 100.3 % | 5.2 % | yes |
| tls | download | 8 MiB | 248.4 | 257.4 | 96.5 % | 3.3 % | yes |
| tls | download | 32 MiB | 251.6 | 227.3 | 110.7 % | 6.6 % | yes |
| tls | download | 128 MiB | 256.0 | 235.7 | 108.6 % | 4.1 % | yes |
| tls | upload | 1 KiB | 0.7 | 0.8 | 91.2 % | 21.9 % | **no** |
| tls | upload | 64 KiB | 32.1 | 42.9 | 74.9 % | 21.7 % | **no** |
| tls | upload | 256 KiB | 58.5 | 72.4 | 80.8 % | 7.7 % | yes |
| tls | upload | 1 MiB | 93.5 | 121.2 | 77.1 % | 11.1 % | **no** |
| tls | upload | 4 MiB | 109.4 | 145.3 | 75.3 % | 10.0 % | **no** |
| tls | upload | 5 MiB | 86.4 | 153.0 | 56.5 % | 4.8 % | yes |
| tls | upload | 8 MiB | 89.8 | 151.6 | 59.2 % | 3.5 % | yes |
| tls | upload | 32 MiB | 107.5 | 193.8 | 55.5 % | 4.7 % | yes |
| tls | upload | 128 MiB | 107.4 | 233.2 | 46.1 % | 24.5 % | **no** |

## Ranged read — proxy against direct backend

| Transport | Operation | Size | Proxy (MiB/s) | Direct (MiB/s) | Ratio | Proxy RSD | Stable |
|---|---|---|---:|---:|---:|---:|:--:|
| http | range_mid_aligned | 64 KiB | 55.0 | 68.7 | 80.0 % | 7.7 % | yes |
| http | range_mid_aligned | 1 MiB | 207.2 | 216.8 | 95.6 % | 4.5 % | yes |
| http | range_mid_aligned | 8 MiB | 253.1 | 251.8 | 100.5 % | 3.2 % | yes |
| http | range_mid_unaligned | 64 KiB | 55.0 | 82.5 | 66.6 % | 11.6 % | **no** |
| http | range_mid_unaligned | 1 MiB | 210.0 | 218.9 | 95.9 % | 4.7 % | yes |
| http | range_mid_unaligned | 8 MiB | 258.4 | 250.5 | 103.2 % | 2.3 % | yes |
| http | range_start | 64 KiB | 42.4 | 53.2 | 79.8 % | 11.1 % | **no** |
| http | range_start | 1 MiB | 217.9 | 228.2 | 95.5 % | 4.5 % | yes |
| http | range_start | 8 MiB | 256.6 | 252.7 | 101.6 % | 1.4 % | yes |
| http | range_tail | 64 KiB | 53.8 | 79.4 | 67.7 % | 8.9 % | **no** |
| http | range_tail | 1 MiB | 200.8 | 224.4 | 89.5 % | 4.4 % | yes |
| http | range_tail | 8 MiB | 257.2 | 250.2 | 102.8 % | 2.0 % | yes |
| tls | range_mid_aligned | 64 KiB | 54.2 | 62.7 | 86.4 % | 11.5 % | **no** |
| tls | range_mid_aligned | 1 MiB | 192.4 | 214.6 | 89.6 % | 6.2 % | yes |
| tls | range_mid_aligned | 8 MiB | 238.2 | 256.6 | 92.8 % | 5.9 % | yes |
| tls | range_mid_unaligned | 64 KiB | 61.2 | 73.9 | 82.8 % | 7.9 % | **no** |
| tls | range_mid_unaligned | 1 MiB | 196.1 | 225.7 | 86.9 % | 4.7 % | yes |
| tls | range_mid_unaligned | 8 MiB | 240.0 | 254.3 | 94.4 % | 4.0 % | yes |
| tls | range_start | 64 KiB | 39.8 | 51.6 | 77.1 % | 5.7 % | yes |
| tls | range_start | 1 MiB | 202.5 | 210.5 | 96.2 % | 3.5 % | yes |
| tls | range_start | 8 MiB | 235.5 | 249.3 | 94.4 % | 3.2 % | yes |
| tls | range_tail | 64 KiB | 50.7 | 65.4 | 77.5 % | 6.2 % | yes |
| tls | range_tail | 1 MiB | 182.5 | 213.3 | 85.6 % | 6.1 % | yes |
| tls | range_tail | 8 MiB | 239.5 | 250.5 | 95.6 % | 5.5 % | yes |

## Small objects — request rate

| Transport | Operation | Size | Proxy (ops/s) | Direct (ops/s) | Ratio | Proxy RSD | Stable |
|---|---|---|---:|---:|---:|---:|:--:|
| http | get_rate_c1 | 1 KiB | 1777.7 | 2973.6 | 59.8 % | 2.7 % | yes |
| http | get_rate_c1 | 16 KiB | 1497.7 | 2452.1 | 61.1 % | 4.5 % | yes |
| http | get_rate_c1 | 64 KiB | 1176.3 | 1711.7 | 68.7 % | 6.2 % | yes |
| http | get_rate_c32 | 1 KiB | 1930.2 | 7835.0 | 24.6 % | 12.9 % | **no** |
| http | get_rate_c32 | 16 KiB | 1852.1 | 5965.8 | 31.0 % | 8.5 % | **no** |
| http | get_rate_c32 | 64 KiB | 1538.7 | 3155.7 | 48.8 % | 4.1 % | yes |
| http | get_rate_c8 | 1 KiB | 2357.4 | 8303.6 | 28.4 % | 8.4 % | **no** |
| http | get_rate_c8 | 16 KiB | 2065.7 | 7224.8 | 28.6 % | 5.8 % | **no** |
| http | get_rate_c8 | 64 KiB | 1689.0 | 3237.7 | 52.2 % | 4.5 % | yes |
| http | put_rate_c1 | 1 KiB | 407.0 | 449.5 | 90.5 % | 5.5 % | **no** |
| http | put_rate_c1 | 16 KiB | 366.6 | 417.0 | 87.9 % | 15.6 % | **no** |
| http | put_rate_c1 | 64 KiB | 309.6 | 377.1 | 82.1 % | 8.5 % | **no** |
| http | put_rate_c32 | 1 KiB | 902.9 | 1463.5 | 61.7 % | 7.7 % | **no** |
| http | put_rate_c32 | 16 KiB | 822.9 | 1232.4 | 66.8 % | 7.2 % | yes |
| http | put_rate_c32 | 64 KiB | 661.6 | 910.2 | 72.7 % | 7.8 % | yes |
| http | put_rate_c8 | 1 KiB | 1072.3 | 2169.2 | 49.4 % | 19.1 % | **no** |
| http | put_rate_c8 | 16 KiB | 802.8 | 1017.7 | 78.9 % | 7.3 % | **no** |
| http | put_rate_c8 | 64 KiB | 932.3 | 1142.0 | 81.6 % | 14.3 % | **no** |
| tls | get_rate_c1 | 1 KiB | 1766.3 | 2957.1 | 59.7 % | 2.6 % | yes |
| tls | get_rate_c1 | 16 KiB | 1540.8 | 2487.3 | 61.9 % | 2.8 % | yes |
| tls | get_rate_c1 | 64 KiB | 1099.9 | 1702.8 | 64.6 % | 2.2 % | yes |
| tls | get_rate_c32 | 1 KiB | 1952.1 | 7547.8 | 25.9 % | 9.6 % | **no** |
| tls | get_rate_c32 | 16 KiB | 1758.1 | 5771.4 | 30.5 % | 8.5 % | **no** |
| tls | get_rate_c32 | 64 KiB | 1576.1 | 3454.0 | 45.6 % | 2.5 % | yes |
| tls | get_rate_c8 | 1 KiB | 2108.2 | 8362.9 | 25.2 % | 6.1 % | **no** |
| tls | get_rate_c8 | 16 KiB | 2079.1 | 6606.8 | 31.5 % | 3.2 % | yes |
| tls | get_rate_c8 | 64 KiB | 1761.0 | 3379.4 | 52.1 % | 2.9 % | yes |
| tls | put_rate_c1 | 1 KiB | 484.2 | 588.1 | 82.3 % | 12.0 % | **no** |
| tls | put_rate_c1 | 16 KiB | 439.9 | 587.7 | 74.8 % | 5.5 % | yes |
| tls | put_rate_c1 | 64 KiB | 312.9 | 404.9 | 77.3 % | 4.2 % | yes |
| tls | put_rate_c32 | 1 KiB | 911.9 | 1493.9 | 61.0 % | 4.0 % | yes |
| tls | put_rate_c32 | 16 KiB | 813.0 | 1328.8 | 61.2 % | 5.8 % | yes |
| tls | put_rate_c32 | 64 KiB | 658.9 | 880.3 | 74.9 % | 3.0 % | yes |
| tls | put_rate_c8 | 1 KiB | 894.0 | 1065.0 | 83.9 % | 18.9 % | **no** |
| tls | put_rate_c8 | 16 KiB | 950.4 | 1430.7 | 66.4 % | 15.0 % | **no** |
| tls | put_rate_c8 | 64 KiB | 874.5 | 1229.0 | 71.2 % | 8.7 % | yes |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 145.5 | ns/op | 5.6 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 629292 | ns/op | 0.2 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3799931 | ns/op | 0.2 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 340.1 | ns/op | 1.8 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 20412 | ns/op | 1.3 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 101214 | ns/op | 3.1 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | crc32c | 64 KiB | 10344 | MiB/s | 2.5 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 1 MiB | 10494 | MiB/s | 2.9 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 12 MiB | 11380 | MiB/s | 2.5 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | crc32c | 128 MiB | 11131 | MiB/s | 2.6 % | 7 | plaintext checksum the v2 trailer adds |
| in-process | ctr_encrypt | 64 KiB | 7500 | MiB/s | 40.1 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 1 MiB | 10033 | MiB/s | 5.1 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 12 MiB | 10374 | MiB/s | 1.9 % | 7 | AES-CTR only |
| in-process | ctr_encrypt | 128 MiB | 10475 | MiB/s | 1.3 % | 7 | AES-CTR only |
| in-process | hmac_only | 64 KiB | 2412 | MiB/s | 28.9 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 1 MiB | 2729 | MiB/s | 3.0 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 12 MiB | 3042 | MiB/s | 1.4 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | hmac_only | 128 MiB | 3092 | MiB/s | 1.3 % | 7 | HMAC-SHA256 over the plaintext |
| in-process | v1_ctr_hmac_decrypt | 64 KiB | 2161 | MiB/s | 3.2 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 1 MiB | 2201 | MiB/s | 1.7 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 12 MiB | 2371 | MiB/s | 1.6 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_decrypt | 128 MiB | 2400 | MiB/s | 3.1 % | 7 | current read path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 64 KiB | 2052 | MiB/s | 11.5 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 1 MiB | 2183 | MiB/s | 2.3 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 12 MiB | 2366 | MiB/s | 0.2 % | 7 | current write path above the threshold |
| in-process | v1_ctr_hmac_encrypt | 128 MiB | 2429 | MiB/s | 1.0 % | 7 | current write path above the threshold |
| in-process | v1_gcm_whole_decrypt | 64 KiB | 8427 | MiB/s | 0.7 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 1 MiB | 8664 | MiB/s | 2.7 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 12 MiB | 8728 | MiB/s | 17.5 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_decrypt | 128 MiB | 8694 | MiB/s | 10.8 % | 7 | current read path below the threshold |
| in-process | v1_gcm_whole_encrypt | 64 KiB | 7894 | MiB/s | 0.8 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 1 MiB | 8013 | MiB/s | 6.3 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 12 MiB | 8155 | MiB/s | 12.8 % | 7 | current write path below the threshold |
| in-process | v1_gcm_whole_encrypt | 128 MiB | 8239 | MiB/s | 8.5 % | 7 | current write path below the threshold |
| in-process | v2_gcm_seg_decrypt | 64 KiB | 8380 | MiB/s | 0.5 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 1 MiB | 8652 | MiB/s | 2.2 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 12 MiB | 8822 | MiB/s | 9.3 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_decrypt | 128 MiB | 8692 | MiB/s | 23.1 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 64 KiB | 7894 | MiB/s | 0.6 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 1 MiB | 7908 | MiB/s | 1.1 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 12 MiB | 8042 | MiB/s | 2.8 % | 7 | segmented AES-GCM candidate, 64 KiB segments |
| in-process | v2_gcm_seg_encrypt | 128 MiB | 8150 | MiB/s | 1.3 % | 7 | segmented AES-GCM candidate, 64 KiB segments |

## Proxy resident memory

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| proxy | rss_cold | — | 23539712 | bytes | 0.0 % | 1 | resident memory before this run touched the proxy — recorded, not asserted |
| proxy | rss_cold_load_peak | — | 147558400 | bytes | 0.0 % | 1 | peak during the first (warm-up) load, i.e. what reaching the settled level costs — recorded, not asserted |
| proxy | rss_idle | — | 102408192 | bytes | 12.2 % | 7 | process_resident_memory_bytes before each repetition's load; after the warm-up this is the settled level, not a cold process — recorded, not asserted |
| proxy | rss_limit | — | 536870912 | bytes | 0.0 % | 1 | container memory limit from docker-compose.demo.yml — recorded, not asserted |
| proxy | rss_peak | — | 130093056 | bytes | 7.8 % | 7 | maximum of a 250ms sample while 2×128 MiB PUT+GET plus 1 MiB PUT+GET ran — recorded, not asserted |
| proxy | rss_peak_minus_idle | — | 24309760 | bytes | 60.8 % | 7 | what the load itself costs; the bound of ADR 0020 D14 applies to this figure — recorded, not asserted |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
