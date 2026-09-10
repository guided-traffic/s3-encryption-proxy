# Errors

Every failure a client sees is an S3 `<Error>` document with an S3 error code.
`http.Error` is a bug on any path a client reaches: the SDK cannot parse a code
out of a text body and synthesises one from the status line, so the real reason
never arrives.

Code: `internal/proxy/response/`.

## Choosing a status class

The rule that matters most is not which code but **which class**, because the
class decides what the client's SDK does next.

**A permanent state of the object is a 4xx.** A 5xx makes an SDK retry a request
that cannot succeed — measured at three backend requests per client read — and
makes a client that treats 5xx as transient file a corruption as a passing
outage. Both are wrong answers to "this object is not readable here".

**A transient failure is a 5xx**, because there a retry is exactly right. A KMS
that cannot be reached, a backend that timed out.

The line runs through the cause, not through the symptom. A wrapped key that
fails its authentication tag is permanent, so it is 403. The same call failing
because the key provider is unreachable would be 5xx.

## The refusals worth knowing

| Situation | Answer |
|---|---|
| Object carries no proxy metadata, or names a foreign format | `403 InvalidObjectState`, *Object is not encrypted by this proxy* |
| The wrapped data key fails its authentication tag | `403 InvalidObjectState`, *Object key material failed authentication* |
| Server-side copy under encryption | `422 NotSupportedWithEncryption` |
| A verb or sub-resource that is not implemented | `501 NotImplemented` |
| A multipart part layout that cannot be stored as a chain | `400 InvalidPart`, and the upload is aborted |
| A completion list that does not describe the upload | `400 InvalidPart`, and the upload survives |
| A second short part in one session | `400 EntityTooSmall`, at upload time |
| The short-part buffer is full | `503 SlowDown`, and the upload survives |
| An unknown upload id | `404 NoSuchUpload` |

`NotSupportedWithEncryption` and its 422 are the proxy's own, not codes AWS
defines. How clients surface them is not verified.

## Aborting a body

Once a status line is out there is no code left to send. A fault found while
streaming is reported by **aborting the response body**, which reaches the client
as an unexpected EOF. Prefer to decide a refusal before the response begins where
the information is available — that is why the metadata checks run before the
first backend byte is read.

## What never reaches a client

Backend error text, which the storage endpoint controls; the backend endpoint
name; authentication failure detail, which carries attacker-controlled text —
reflecting it echoed that text into the response body and broke the XML whenever
a key contained `&` or `<`. All of it is logged instead.
