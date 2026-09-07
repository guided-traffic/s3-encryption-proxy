# Binary Test Fixture

> 14 nodes · cohesion 0.21

## Key Concepts

- **papagei.jpg binary test fixture** (10 connections) — `test/example-files/papagei.jpg`
- **test/integration/ MinIO-backed integration suite (assumed consumer)** (3 connections) — `test/example-files/papagei.jpg`
- **JPEG/JFIF 1.01, progressive, 8-bit, 3 components, 640x427, 37739 bytes** (3 connections) — `test/example-files/papagei.jpg`
- **Byte-exact encrypt/decrypt round-trip fidelity for binary payloads** (3 connections) — `test/example-files/papagei.jpg`
- **Non-text Content-Type carrier (image/jpeg) for metadata and header passthrough checks** (2 connections) — `test/example-files/papagei.jpg`
- **start-demo.sh manual browse check: same object via encrypted proxy vs direct MinIO explorer** (2 connections) — `test/example-files/papagei.jpg`
- **Two collared aracaris perched on a mossy branch (rainforest bokeh)** (2 connections) — `test/example-files/papagei.jpg`
- **Encryption-at-rest assertion: backend bytes must not equal the fixture bytes** (2 connections) — `test/example-files/papagei.jpg`
- **test/example-files/ fixture corpus (text.txt, local_random_10mb/100mb/1gb/2gb, papagei.jpg)** (2 connections) — `test/example-files/papagei.jpg`
- **Already-compressed high-entropy payload, hostile to accidental plaintext survival** (2 connections) — `test/example-files/papagei.jpg`
- **Filename/subject mismatch: papagei means parrot, image shows toucans (aracaris)** (2 connections) — `test/example-files/papagei.jpg`
- **SHA-256 698845047afe623a6216978953468f82dcae46de1d3fbd4706c0d4f7df2ecddd** (2 connections) — `test/example-files/papagei.jpg`
- **Small-object path: 37 KB stays far below streaming_threshold, so AES-GCM whole-object encryption** (2 connections) — `test/example-files/papagei.jpg`
- **test/e2e/velero/ backup/restore e2e suite (possible consumer)** (1 connections) — `test/example-files/papagei.jpg`

## Relationships

- No strong cross-community connections detected

## Source Files

- `test/example-files/papagei.jpg`

## Audit Trail

- EXTRACTED: 10 (26%)
- INFERRED: 20 (53%)
- AMBIGUOUS: 8 (21%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*