# Performance baseline — wave3-checksums

Run `20260911T064137Z-233d559`, schema 1. 2026-09-11T06:41:37Z → 2026-09-11T06:47:33Z (355 s), 7 repetitions per point.

Commit `233d5593f9614495376d66ba665243afa372e3b5` on `feat/major-v5`.

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
| Load average before | 4.17 / 4.54 / 3.61 |
| Load average after | 5.70 / 5.10 / 4.19 |

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
| memory | skipped | process_resident_memory_bytes not exported at http://127.0.0.1:9090/metrics |
| profiles | ok | — |
| rangeread | ok | — |
| smallobject | ok | — |
| throughput | ok | — |
| unwrap | ok | — |
| uploadpath | skipped | set S3EP_PERF_ALT_PROXY to a proxy whose streaming_segment_size is above every size measured here; see the comment on altProxyEnv |

## Throughput — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | download | 1 KiB | proxy | 1.4 | 2.2 | 61.7 % | 10.2 % | **no** |
| http | download | 64 KiB | proxy | 67.6 | 98.8 | 68.4 % | 5.0 % | yes |
| http | download | 256 KiB | proxy | 146.4 | 173.1 | 84.6 % | 5.6 % | yes |
| http | download | 1 MiB | proxy | 218.7 | 219.0 | 99.9 % | 8.5 % | yes |
| http | download | 4 MiB | proxy | 255.1 | 243.3 | 104.8 % | 3.6 % | yes |
| http | download | 5 MiB | proxy | 252.3 | 253.3 | 99.6 % | 2.4 % | yes |
| http | download | 8 MiB | proxy | 259.0 | 244.5 | 105.9 % | 2.1 % | yes |
| http | download | 32 MiB | proxy | 257.9 | 253.0 | 101.9 % | 4.5 % | yes |
| http | download | 128 MiB | proxy | 253.1 | 247.3 | 102.3 % | 1.2 % | yes |
| http | upload | 1 KiB | proxy | 0.6 | 1.0 | 65.3 % | 27.1 % | **no** |
| http | upload | 64 KiB | proxy | 43.2 | 47.6 | 90.8 % | 14.8 % | **no** |
| http | upload | 256 KiB | proxy | 77.1 | 85.7 | 90.0 % | 8.5 % | **no** |
| http | upload | 1 MiB | proxy | 128.8 | 127.9 | 100.7 % | 10.7 % | **no** |
| http | upload | 4 MiB | proxy | 172.9 | 156.2 | 110.6 % | 5.0 % | yes |
| http | upload | 5 MiB | proxy | 181.5 | 163.1 | 111.3 % | 4.8 % | yes |
| http | upload | 8 MiB | proxy | 185.7 | 159.9 | 116.1 % | 7.2 % | yes |
| http | upload | 32 MiB | proxy | 193.2 | 221.6 | 87.2 % | 5.8 % | yes |
| http | upload | 128 MiB | proxy | 254.0 | 257.9 | 98.5 % | 16.3 % | **no** |
| tls | download | 1 KiB | proxy | 1.7 | 3.1 | 55.8 % | 7.9 % | yes |
| tls | download | 64 KiB | proxy | 74.6 | 108.6 | 68.7 % | 3.5 % | yes |
| tls | download | 256 KiB | proxy | 141.6 | 174.8 | 81.0 % | 8.1 % | yes |
| tls | download | 1 MiB | proxy | 206.7 | 218.6 | 94.6 % | 3.9 % | yes |
| tls | download | 4 MiB | proxy | 242.2 | 235.8 | 102.7 % | 3.5 % | yes |
| tls | download | 5 MiB | proxy | 234.4 | 243.1 | 96.4 % | 5.6 % | yes |
| tls | download | 8 MiB | proxy | 243.4 | 253.7 | 95.9 % | 4.0 % | yes |
| tls | download | 32 MiB | proxy | 255.9 | 255.7 | 100.1 % | 3.4 % | yes |
| tls | download | 128 MiB | proxy | 255.0 | 248.5 | 102.6 % | 2.5 % | yes |
| tls | upload | 1 KiB | proxy | 0.9 | 1.2 | 76.0 % | 11.6 % | **no** |
| tls | upload | 64 KiB | proxy | 41.4 | 54.4 | 76.2 % | 12.8 % | **no** |
| tls | upload | 256 KiB | proxy | 94.2 | 93.1 | 101.1 % | 10.1 % | **no** |
| tls | upload | 1 MiB | proxy | 137.4 | 132.4 | 103.8 % | 4.5 % | yes |
| tls | upload | 4 MiB | proxy | 173.8 | 159.5 | 109.0 % | 7.4 % | yes |
| tls | upload | 5 MiB | proxy | 198.4 | 159.8 | 124.1 % | 5.9 % | yes |
| tls | upload | 8 MiB | proxy | 188.3 | 161.0 | 117.0 % | 2.7 % | yes |
| tls | upload | 32 MiB | proxy | 203.0 | 218.6 | 92.9 % | 2.7 % | yes |
| tls | upload | 128 MiB | proxy | 243.3 | 246.9 | 98.5 % | 3.3 % | yes |

## Ranged read — proxy against direct backend

| Transport | Operation | Size | Subject | MiB/s | direct (MiB/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | range_mid_aligned | 64 KiB | proxy | 50.9 | 67.9 | 75.0 % | 6.8 % | yes |
| http | range_mid_aligned | 1 MiB | proxy | 153.8 | 225.8 | 68.1 % | 3.5 % | yes |
| http | range_mid_aligned | 8 MiB | proxy | 240.7 | 253.0 | 95.2 % | 4.1 % | yes |
| http | range_mid_unaligned | 64 KiB | proxy | 57.7 | 76.2 | 75.8 % | 5.5 % | yes |
| http | range_mid_unaligned | 1 MiB | proxy | 162.1 | 222.1 | 73.0 % | 2.1 % | yes |
| http | range_mid_unaligned | 8 MiB | proxy | 245.0 | 248.7 | 98.5 % | 3.2 % | yes |
| http | range_start | 64 KiB | proxy | 40.9 | 53.7 | 76.1 % | 1.8 % | yes |
| http | range_start | 1 MiB | proxy | 215.2 | 222.4 | 96.8 % | 4.3 % | yes |
| http | range_start | 8 MiB | proxy | 258.2 | 251.8 | 102.6 % | 2.1 % | yes |
| http | range_tail | 64 KiB | proxy | 54.3 | 69.8 | 77.7 % | 5.0 % | yes |
| http | range_tail | 1 MiB | proxy | 164.4 | 228.9 | 71.8 % | 1.6 % | yes |
| http | range_tail | 8 MiB | proxy | 244.1 | 250.5 | 97.4 % | 2.9 % | yes |
| tls | range_mid_aligned | 64 KiB | proxy | 50.2 | 69.2 | 72.6 % | 2.8 % | yes |
| tls | range_mid_aligned | 1 MiB | proxy | 155.2 | 224.6 | 69.1 % | 2.2 % | yes |
| tls | range_mid_aligned | 8 MiB | proxy | 241.6 | 251.0 | 96.2 % | 1.3 % | yes |
| tls | range_mid_unaligned | 64 KiB | proxy | 56.0 | 81.1 | 69.1 % | 3.0 % | yes |
| tls | range_mid_unaligned | 1 MiB | proxy | 156.0 | 225.3 | 69.3 % | 1.7 % | yes |
| tls | range_mid_unaligned | 8 MiB | proxy | 240.5 | 257.1 | 93.5 % | 3.0 % | yes |
| tls | range_start | 64 KiB | proxy | 40.3 | 58.3 | 69.1 % | 2.5 % | yes |
| tls | range_start | 1 MiB | proxy | 205.8 | 233.5 | 88.2 % | 3.9 % | yes |
| tls | range_start | 8 MiB | proxy | 257.3 | 252.6 | 101.9 % | 2.2 % | yes |
| tls | range_tail | 64 KiB | proxy | 53.7 | 74.6 | 71.9 % | 3.4 % | **no** |
| tls | range_tail | 1 MiB | proxy | 151.5 | 216.1 | 70.1 % | 3.3 % | yes |
| tls | range_tail | 8 MiB | proxy | 242.1 | 256.9 | 94.2 % | 1.9 % | yes |

## Small objects — request rate

| Transport | Operation | Size | Subject | ops/s | direct (ops/s) | Ratio | RSD | Stable |
|---|---|---|---|---:|---:|---:|---:|:--:|
| http | get_rate_c1 | 1 KiB | proxy | 1773.8 | 2888.8 | 61.4 % | 2.4 % | yes |
| http | get_rate_c1 | 16 KiB | proxy | 1585.0 | 2520.0 | 62.9 % | 2.0 % | yes |
| http | get_rate_c1 | 64 KiB | proxy | 1220.3 | 1700.1 | 71.8 % | 2.4 % | yes |
| http | get_rate_c32 | 1 KiB | proxy | 3057.1 | 8096.6 | 37.8 % | 20.5 % | **no** |
| http | get_rate_c32 | 16 KiB | proxy | 2615.3 | 6917.3 | 37.8 % | 8.1 % | **no** |
| http | get_rate_c32 | 64 KiB | proxy | 2317.1 | 3105.5 | 74.6 % | 9.8 % | yes |
| http | get_rate_c8 | 1 KiB | proxy | 5638.8 | 7777.9 | 72.5 % | 8.9 % | **no** |
| http | get_rate_c8 | 16 KiB | proxy | 4858.9 | 5487.8 | 88.5 % | 17.8 % | **no** |
| http | get_rate_c8 | 64 KiB | proxy | 2686.9 | 3111.2 | 86.4 % | 6.2 % | yes |
| http | put_rate_c1 | 1 KiB | proxy | 714.2 | 812.8 | 87.9 % | 9.8 % | **no** |
| http | put_rate_c1 | 16 KiB | proxy | 581.5 | 687.3 | 84.6 % | 33.9 % | **no** |
| http | put_rate_c1 | 64 KiB | proxy | 449.9 | 541.4 | 83.1 % | 3.0 % | yes |
| http | put_rate_c32 | 1 KiB | proxy | 1182.8 | 1380.2 | 85.7 % | 6.6 % | **no** |
| http | put_rate_c32 | 16 KiB | proxy | 1146.2 | 1343.4 | 85.3 % | 13.5 % | **no** |
| http | put_rate_c32 | 64 KiB | proxy | 800.8 | 838.2 | 95.5 % | 32.1 % | **no** |
| http | put_rate_c8 | 1 KiB | proxy | 1351.2 | 1417.2 | 95.3 % | 13.4 % | **no** |
| http | put_rate_c8 | 16 KiB | proxy | 1067.8 | 1616.4 | 66.1 % | 31.4 % | **no** |
| http | put_rate_c8 | 64 KiB | proxy | 1037.9 | 1126.6 | 92.1 % | 11.4 % | **no** |
| tls | get_rate_c1 | 1 KiB | proxy | 1701.1 | 2867.8 | 59.3 % | 3.8 % | yes |
| tls | get_rate_c1 | 16 KiB | proxy | 1504.3 | 2333.2 | 64.5 % | 3.3 % | yes |
| tls | get_rate_c1 | 64 KiB | proxy | 1148.5 | 1630.3 | 70.4 % | 1.8 % | yes |
| tls | get_rate_c32 | 1 KiB | proxy | 3728.8 | 7955.6 | 46.9 % | 21.0 % | **no** |
| tls | get_rate_c32 | 16 KiB | proxy | 2715.9 | 6094.1 | 44.6 % | 14.4 % | **no** |
| tls | get_rate_c32 | 64 KiB | proxy | 2484.2 | 3233.3 | 76.8 % | 11.3 % | **no** |
| tls | get_rate_c8 | 1 KiB | proxy | 4477.3 | 8558.5 | 52.3 % | 11.5 % | **no** |
| tls | get_rate_c8 | 16 KiB | proxy | 4221.9 | 5265.9 | 80.2 % | 9.0 % | **no** |
| tls | get_rate_c8 | 64 KiB | proxy | 2457.4 | 2845.3 | 86.4 % | 10.5 % | **no** |
| tls | put_rate_c1 | 1 KiB | proxy | 657.6 | 860.4 | 76.4 % | 14.2 % | **no** |
| tls | put_rate_c1 | 16 KiB | proxy | 394.3 | 446.2 | 88.4 % | 30.7 % | **no** |
| tls | put_rate_c1 | 64 KiB | proxy | 498.4 | 596.9 | 83.5 % | 9.9 % | **no** |
| tls | put_rate_c32 | 1 KiB | proxy | 1308.9 | 1291.6 | 101.3 % | 5.5 % | **no** |
| tls | put_rate_c32 | 16 KiB | proxy | 1034.7 | 1185.1 | 87.3 % | 4.5 % | **no** |
| tls | put_rate_c32 | 64 KiB | proxy | 796.0 | 869.7 | 91.5 % | 6.6 % | yes |
| tls | put_rate_c8 | 1 KiB | proxy | 1500.5 | 1852.2 | 81.0 % | 8.6 % | **no** |
| tls | put_rate_c8 | 16 KiB | proxy | 1705.5 | 2008.4 | 84.9 % | 15.0 % | **no** |
| tls | put_rate_c8 | 64 KiB | proxy | 1069.6 | 1134.4 | 94.3 % | 7.6 % | yes |

## Key unwrap

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| aes-256 | unwrap_dek | — | 537.1 | ns/op | 7.2 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-2048 | unwrap_dek | — | 647668 | ns/op | 1.6 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| rsa-4096 | unwrap_dek | — | 3805214 | ns/op | 0.3 % | 7 | KEK unwrap on the read path, in process, no DEK cache |
| aes-256 | wrap_dek | — | 946.5 | ns/op | 4.2 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-2048 | wrap_dek | — | 20857 | ns/op | 2.9 % | 7 | KEK wrap of a 32-byte DEK, in process |
| rsa-4096 | wrap_dek | — | 101032 | ns/op | 2.2 % | 7 | KEK wrap of a 32-byte DEK, in process |

## In-process crypto floor

| Subject | Operation | Size | Median | Unit | RSD | n | Note |
|---|---|---|---:|---|---:|---:|---|
| in-process | codec_decrypt | 64 KiB | 2239 | MiB/s | 16.5 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 1 MiB | 3834 | MiB/s | 13.8 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 12 MiB | 4456 | MiB/s | 2.7 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_decrypt | 128 MiB | 4394 | MiB/s | 0.5 % | 7 | the shipped segment codec, trailer verified |
| in-process | codec_encrypt | 64 KiB | 2290 | MiB/s | 58.8 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 1 MiB | 3787 | MiB/s | 2.5 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 12 MiB | 4493 | MiB/s | 0.8 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | codec_encrypt | 128 MiB | 4383 | MiB/s | 1.3 % | 7 | the shipped segment codec, trailer and CRC included |
| in-process | crc32c | 64 KiB | 7854 | MiB/s | 8.2 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 1 MiB | 9467 | MiB/s | 4.1 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 12 MiB | 11456 | MiB/s | 1.9 % | 7 | plaintext checksum the trailer carries |
| in-process | crc32c | 128 MiB | 11215 | MiB/s | 2.9 % | 7 | plaintext checksum the trailer carries |
| in-process | gcm_seg_decrypt | 64 KiB | 6465 | MiB/s | 4.8 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 1 MiB | 7479 | MiB/s | 3.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 12 MiB | 8844 | MiB/s | 0.8 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_decrypt | 128 MiB | 8906 | MiB/s | 0.4 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 64 KiB | 6250 | MiB/s | 8.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 1 MiB | 7205 | MiB/s | 1.6 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 12 MiB | 8064 | MiB/s | 2.9 % | 7 | per-segment AES-GCM only, no trailer and no checksum |
| in-process | gcm_seg_encrypt | 128 MiB | 8291 | MiB/s | 0.5 % | 7 | per-segment AES-GCM only, no trailer and no checksum |


---

A row marked unstable has a relative standard deviation above 10 %; it carries no comparison value against another run.
