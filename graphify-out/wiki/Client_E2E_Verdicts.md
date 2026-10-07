# Client E2E Verdicts

> 19 nodes · cohesion 0.11

## Key Concepts

- **Entity tag is a change token with a -0 marker** (7 connections) — `docs/operations/integrity.md`
- **s3cmd** (4 connections) — `docs/operations/clients/s3cmd.md`
- **What a read costs (tail-first whole-object GET)** (4 connections) — `docs/operations/s3-api.md`
- **The first read of a whole-object GET (evaluation)** (4 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **rclone** (3 connections) — `docs/operations/clients/rclone.md`
- **Option C — issue the second request on the first answer's headers** (3 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **A client suite asserts the target behaviour** (2 connections) — `docs/developer/testing.md`
- **use_multipart_etag = false** (2 connections) — `docs/operations/clients/rclone.md`
- **s3cmd sends no Content-MD5 for an object body** (2 connections) — `docs/operations/clients/s3cmd.md`
- **x-amz-checksum-crc32c answered on write, GET and HEAD** (2 connections) — `docs/operations/integrity.md`
- **Window options A, B, D and E** (2 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **The second backend round trip costs small reads** (2 connections) — `docs/tickets/027-whole-object-read-first-window.md`
- **test/perf baseline records, never asserts throughput** (1 connections) — `docs/developer/testing.md`
- **e2e verdict table (Still broken section)** (1 connections) — `docs/developer/testing.md`
- **rclone's X-Amz-Meta-Md5chksum annotation** (1 connections) — `docs/operations/clients/rclone.md`
- **host_bucket must equal host_base (path style)** (1 connections) — `docs/operations/clients/s3cmd.md`
- **Conditional requests forwarded to the backend** (1 connections) — `docs/operations/s3-api.md`
- **Listing parameters and the max-keys clamp** (1 connections) — `docs/operations/s3-api.md`
- **serveWholeObject** (1 connections) — `docs/tickets/027-whole-object-read-first-window.md`

## Relationships

- [CI Pipeline and Renovate Jobs](CI_Pipeline_and_Renovate_Jobs.md) (2 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (2 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (2 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (2 shared connections)

## Source Files

- `docs/developer/testing.md`
- `docs/operations/clients/rclone.md`
- `docs/operations/clients/s3cmd.md`
- `docs/operations/integrity.md`
- `docs/operations/s3-api.md`
- `docs/tickets/027-whole-object-read-first-window.md`

## Audit Trail

- EXTRACTED: 23 (88%)
- INFERRED: 3 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*