# Where the upload deficit actually is

The `pre-v2` run measured that the proxy uploads at 56–60 % of the backend behind it from
5 MiB up, and reads at parity. This run decomposes that deficit. It falsifies the explanation
the `pre-v2` findings proposed and identifies the real one.

Same machine as the other runs, 7 repetitions, leg order alternating — but **on battery,
where the other two runs were on mains**. The three legs here were measured together and are
comparable with each other; figures from this run must not be compared with the `pre-v2` or
codec runs (ADR 0020 D19).

## The self-copy is not the cause

After every multipart completion the proxy copies the object onto itself with
`MetadataDirective=REPLACE`, because the metadata — the integrity value above all — only
exists once the last part is encrypted, and `CompleteMultipartUpload` accepts none. The
`pre-v2` findings modelled the deficit as that second write and derived, from the measured
ratios, that it would have to run at 231–372 MiB/s.

Timed directly against the backend:

| Object | self-copy |
|---|---:|
| 8 MiB | 4826 MiB/s |
| 32 MiB | 6587 MiB/s |
| 128 MiB | 7485 MiB/s |

**An order of magnitude faster than the model needed.** At 8 MiB the copy costs 1.7 ms of a
33.6 ms gap — about **5 %**. The hypothesis is dead. It fitted three points and was wrong, which
is what a model that has never been checked against the thing it models is worth.

## The proxy is faster than the backend when it streams

Three legs, the same `PutObject` call, the same bytes:

| Size | direct | proxy, streaming path | proxy, auto-multipart |
|---|---:|---:|---:|
| 8 MiB | 164.9 MiB/s | **173.5 (105 %)** | 97.4 (59 %) |
| 12 MiB | 165.8 MiB/s | **172.8 (104 %)*** | 95.3 (57 %) |
| 16 MiB | 165.1 MiB/s | **184.4 (112 %)** | 115.3 (70 %) |

\* the 12 MiB streaming row scatters 10.8 % and is marked unstable; the other two are tight.

The streaming leg is a proxy with `integrity_verification: off`, which routes these sizes onto
the streaming write path instead of auto-multipart. It still encrypts every byte, still crosses
loopback twice, and it is **at or above** the backend it writes to.

So the deficit is none of the things it could plausibly have been:

The gap at 8 MiB is **33.6 ms** — 82.2 ms for the auto-multipart leg against 48.5 ms direct
(36.0 ms against the streaming leg).

| Candidate | Share of the 33.6 ms gap at 8 MiB |
|---|---:|
| the integrity pass | 2.6 ms — **7.7 %** |
| the post-completion self-copy | 1.7 ms — **4.9 %** |
| the second network hop | none: the streaming path pays it and is faster than direct |
| **the auto-multipart write path** | **the remaining 87 %** |

## What the write path does, and what it does not

The tempting explanation — that receiving part *n+1* cannot overlap sending part *n* — is
**contradicted by this run's own table.** With a 12 MiB part size, the 8 MiB and 12 MiB uploads
are a single part: there is no second part to overlap with, and those are the two worst rows.
The 16 MiB upload is two parts and does *better*, 70 % against 57–59 %. More parts helps, so a
per-part pipelining deficit is not the mechanism.

What is structurally different at one part is two things, and this run does not separate them:

- The producer reads the whole body into a buffer before any of it is sent, where the streaming
  path forwards as it reads.
- The multipart route makes four backend calls — create, upload, complete, self-copy — against
  the single `PutObject` the other two legs make.

**Which of those carries the 87 % is not established.** No profile was taken under this load,
and the profile that would answer it — a blocking profile, showing where the producer waits —
is enabled nowhere in the tree. Attribute before fixing.

What the run does settle is the negative: neither the cipher, nor the checksum, nor the second
write, nor the extra network hop is what the ratio pays for.

## What follows for the storage format change

The segment chain makes segments independent, which removes the *reason* the parts had to be
encrypted in sequence, and it deletes the self-copy — worth about 5 %, and one of the four
backend calls. **Neither of those addresses the 87 % on its own.** A write path that still
materialises the whole part before sending it will keep the ratio near 59 %, and the release
would ship a faster cipher with nothing measurable at the edge.

The measurement to repeat after the rewrite is this table, not a crypto benchmark.

## What this run does not tell you

- **Why** the pipeline costs what it does, in the sense of a profile. No CPU or blocking
  profile was taken under this load; the decomposition is by substitution, not by attribution.
  A blocking profile would say whether the producer waits on the client, on the cipher, or on
  the workers — and blocking profiles are not enabled anywhere in the tree today.
- Whether the streaming path stays ahead at sizes above 16 MiB. It cannot be measured with a
  single `PutObject` there: the backend refuses an aws-chunked chunk above 16 MiB, and moving
  the legs to a multipart uploader would change the thing under test.
- Anything about the client-driven multipart path, which is a different producer.
