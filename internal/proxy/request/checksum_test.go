package request

import (
	"bytes"
	"crypto/md5"  // #nosec G501 - Content-MD5 is the digest S3 defines for an upload
	"crypto/sha1" // #nosec G505 - x-amz-checksum-sha1 is a client-declared transmission check
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// The CRC-64/NVME check value: the residue of the ASCII string "123456789",
// which is how every CRC catalogue identifies a parameterisation.
func TestChkCRC64NVMECheckValue(t *testing.T) {
	h := newCRC64NVME()
	if _, err := h.Write([]byte("123456789")); err != nil {
		t.Fatal(err)
	}
	got := h.Sum(nil)
	want := []byte{0xae, 0x8b, 0x14, 0x86, 0x0a, 0x79, 0x98, 0x88}
	if !bytes.Equal(got, want) {
		t.Fatalf("crc64nvme check value = %x, want %x", got, want)
	}
}

// The table is built once at package load, never per Write. hash/crc64 rebuilds
// its slicing-by-8 helper on every Write of 2048 bytes or more for any
// polynomial that is not ISO or ECMA (crc64.go, the len(p) >= 2048 branch); on
// Go 1.27.1 escape analysis keeps that 16 KiB on the stack, so the cost is the
// 8x256 build loop rather than an allocation. BenchmarkChkCRC64NVME reports both
// forms; measured on arm64 the table here is about one percent faster and
// neither allocates.
func TestChkCRC64NVMEAllocatesNothingPerWrite(t *testing.T) {
	block := make([]byte, 128*1024)
	h := newCRC64NVME()
	allocs := testing.AllocsPerRun(20, func() {
		_, _ = h.Write(block)
	})
	if allocs != 0 {
		t.Fatalf("crc64nvme Write allocates %.1f times per call; the table must be built once", allocs)
	}
}

// ---------------------------------------------------------------------------
// The algorithm table the tests drive: how a client computes each value.
// ---------------------------------------------------------------------------

type chkAlgorithm struct {
	// header is what a request header is called; trailer is the aws-chunked
	// trailer name, empty for Content-MD5, which is never a trailer.
	header  string
	trailer string
	digest  func([]byte) []byte
}

var chkAlgorithms = map[string]chkAlgorithm{
	"crc32": {
		header: "x-amz-checksum-crc32", trailer: "x-amz-checksum-crc32",
		digest: func(b []byte) []byte {
			sum := crc32.ChecksumIEEE(b)
			return []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
		},
	},
	"crc32c": {
		header: "x-amz-checksum-crc32c", trailer: "x-amz-checksum-crc32c",
		digest: func(b []byte) []byte {
			sum := crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
			return []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
		},
	},
	"crc64nvme": {
		header: "x-amz-checksum-crc64nvme", trailer: "x-amz-checksum-crc64nvme",
		digest: func(b []byte) []byte {
			h := newCRC64NVME()
			_, _ = h.Write(b)
			return h.Sum(nil)
		},
	},
	"sha1": {
		header: "x-amz-checksum-sha1", trailer: "x-amz-checksum-sha1",
		digest: func(b []byte) []byte { s := sha1.Sum(b); return s[:] }, // #nosec G401
	},
	"sha256": {
		header: "x-amz-checksum-sha256", trailer: "x-amz-checksum-sha256",
		digest: func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
	},
	"md5": {
		header: "Content-MD5",
		digest: func(b []byte) []byte { s := md5.Sum(b); return s[:] }, // #nosec G401
	},
}

func chkEncode(d []byte) string { return base64.StdEncoding.EncodeToString(d) }

func chkParser(t *testing.T) *Parser {
	t.Helper()
	return NewParser(testLogger(), &config.Config{})
}

func chkPayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}

// chkIdentityRequest builds a plain PUT with the payload as its body.
func chkIdentityRequest(payload []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
	r.ContentLength = int64(len(payload))
	return r
}

// ---------------------------------------------------------------------------
// Header-declared values, on both entry points.
// ---------------------------------------------------------------------------

func TestChkHeaderDigestsAreVerified(t *testing.T) {
	payload := chkPayload(4096)

	for name, alg := range chkAlgorithms {
		t.Run(name, func(t *testing.T) {
			correct := chkEncode(alg.digest(payload))

			cases := map[string]struct {
				value     string
				wantErr   error
				wantBytes bool
			}{
				"correct":        {value: correct, wantBytes: true},
				"wrong":          {value: chkEncode(alg.digest([]byte("something else"))), wantErr: ErrChecksumMismatch},
				"not_base64":     {value: "not base64 at all!!", wantErr: ErrChecksumMalformed},
				"wrong_length":   {value: chkEncode([]byte{1, 2, 3}), wantErr: ErrChecksumMalformed},
				"unpadded_is_ok": {value: chkUnpad(correct), wantBytes: true},
			}

			for caseName, tc := range cases {
				t.Run(caseName, func(t *testing.T) {
					p := chkParser(t)

					r := chkIdentityRequest(payload)
					r.Header.Set(alg.header, tc.value)
					got, err := p.ReadBody(r)
					chkAssertOutcome(t, "ReadBody", payload, got, err, tc.wantErr, tc.wantBytes)

					r = chkIdentityRequest(payload)
					r.Header.Set(alg.header, tc.value)
					src, serr := p.StreamingReader(r)
					if serr != nil {
						chkAssertOutcome(t, "StreamingReader", payload, nil, serr, tc.wantErr, tc.wantBytes)
						return
					}
					streamed, rerr := io.ReadAll(src)
					chkAssertOutcome(t, "StreamingReader", payload, streamed, rerr, tc.wantErr, tc.wantBytes)
				})
			}
		})
	}
}

func chkUnpad(v string) string {
	for len(v) > 0 && v[len(v)-1] == '=' {
		v = v[:len(v)-1]
	}
	return v
}

func chkAssertOutcome(
	t *testing.T, entry string, payload, got []byte, err, wantErr error, wantBytes bool,
) {
	t.Helper()
	if wantErr != nil {
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s: error = %v, want %v", entry, err, wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", entry, err)
	}
	if wantBytes && !bytes.Equal(got, payload) {
		t.Fatalf("%s: payload changed under verification", entry)
	}
}

// A declaration the proxy does not recognise is not a checksum and must not be
// treated as one — including the two headers that name an algorithm without
// carrying a value, which every current AWS SDK sends.
func TestChkAlgorithmNameHeadersAreNotDigests(t *testing.T) {
	p := chkParser(t)
	payload := chkPayload(512)

	r := chkIdentityRequest(payload)
	r.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
	r.Header.Set("x-amz-checksum-algorithm", "CRC32")

	if DeclaresChecksum(r) {
		t.Fatal("an algorithm name is not a declared digest")
	}
	got, err := p.ReadBody(r)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadBody: %v", err)
	}
}

// The zero-cost property: a request that declares nothing gets the inner reader
// back with no Read indirection at all. It is easy to lose in a later refactor,
// so it is asserted on the concrete type.
func TestChkNothingDeclaredIsNotWrapped(t *testing.T) {
	p := chkParser(t)

	r := chkIdentityRequest(chkPayload(64))
	src, err := p.StreamingReader(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, wrapped := src.(*checksumReader); wrapped {
		t.Fatal("a request declaring no checksum must not be wrapped")
	}
	if src != io.Reader(r.Body) {
		t.Fatal("StreamingReader must hand back the body itself")
	}
	if Verdict(src) != nil {
		t.Fatal("an unwrapped reader has no verdict")
	}
}

// ---------------------------------------------------------------------------
// Trailer-declared values, across every aws-chunked framing.
// ---------------------------------------------------------------------------

// chkFramed rebuilds one of the wire framings with an arbitrary trailer block,
// so a test can send a correct, wrong, malformed or entirely absent trailer.
func chkFramed(payload []byte, chunkSize int, signed bool, trailers map[string]string) []byte {
	var buf bytes.Buffer
	sig := ""
	if signed {
		sig = ";chunk-signature=deadbeef"
	}
	writeChunks(&buf, payload, chunkSize, sig)
	buf.WriteString("0" + sig + "\r\n")
	for name, value := range trailers {
		fmt.Fprintf(&buf, "%s:%s\r\n", name, value)
	}
	if signed {
		buf.WriteString("x-amz-trailer-signature:deadbeef\r\n")
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}

func chkChunkedRequest(payload, framed []byte, declared string, signed bool) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(framed))
	sha := shaStreamingUnsignedTrailer
	if signed {
		sha = shaStreamingSignedTrailer
	}
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Content-Sha256", sha)
	r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
	if declared != "" {
		r.Header.Set("X-Amz-Trailer", declared)
	}
	r.ContentLength = int64(len(framed))
	return r
}

func TestChkTrailerDigestsAreVerified(t *testing.T) {
	payload := chkPayload(9000)

	for name, alg := range chkAlgorithms {
		if alg.trailer == "" {
			continue // Content-MD5 never arrives as a trailer.
		}
		t.Run(name, func(t *testing.T) {
			correct := chkEncode(alg.digest(payload))

			cases := map[string]struct {
				trailers map[string]string
				wantErr  error
			}{
				"correct": {trailers: map[string]string{alg.trailer: correct}},
				"wrong": {
					trailers: map[string]string{alg.trailer: chkEncode(alg.digest([]byte("other")))},
					wantErr:  ErrChecksumMismatch,
				},
				"not_base64": {
					trailers: map[string]string{alg.trailer: "%%%not base64%%%"},
					wantErr:  ErrChecksumMalformed,
				},
				"wrong_length": {
					trailers: map[string]string{alg.trailer: chkEncode([]byte{9})},
					wantErr:  ErrChecksumMalformed,
				},
				// Declared and never sent is a failed verification, not an
				// absent one (ADR 0012 D5).
				"declared_but_absent": {trailers: nil, wantErr: ErrChecksumMismatch},
			}

			for caseName, tc := range cases {
				for _, signed := range []bool{false, true} {
					for _, chunkSize := range []int{0, 1024} {
						label := fmt.Sprintf("%s/signed=%v/chunk=%d", caseName, signed, chunkSize)
						t.Run(label, func(t *testing.T) {
							p := chkParser(t)
							framed := chkFramed(payload, chunkSize, signed, tc.trailers)

							got, err := p.ReadBody(chkChunkedRequest(payload, framed, alg.trailer, signed))
							chkAssertOutcome(t, "ReadBody", payload, got, err, tc.wantErr, true)

							src, serr := p.StreamingReader(chkChunkedRequest(payload, framed, alg.trailer, signed))
							if serr != nil {
								t.Fatalf("StreamingReader: %v", serr)
							}
							streamed, rerr := io.ReadAll(src)
							chkAssertOutcome(t, "StreamingReader", payload, streamed, rerr, tc.wantErr, true)

							if tc.wantErr != nil && !errors.Is(Verdict(src), tc.wantErr) {
								t.Fatalf("Verdict = %v, want %v", Verdict(src), tc.wantErr)
							}
						})
					}
				}
			}
		})
	}
}

// A trailer block whose last line carries no terminating CRLF is still captured:
// bufio.ReadString hands back the data together with io.EOF, and a decoder that
// returns on the error loses exactly the value the client sent.
func TestChkTrailerWithoutFinalCRLFIsCaptured(t *testing.T) {
	payload := chkPayload(2048)
	alg := chkAlgorithms["crc32"]

	var buf bytes.Buffer
	writeChunks(&buf, payload, 0, "")
	buf.WriteString("0\r\n")
	fmt.Fprintf(&buf, "%s:%s\r\n", alg.trailer, chkEncode(alg.digest(payload)))
	// No terminating blank line.

	p := chkParser(t)
	got, err := p.ReadBody(chkChunkedRequest(payload, buf.Bytes(), alg.trailer, false))
	if err != nil {
		t.Fatalf("a trailer without a final CRLF must still verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
}

// The signature line is not a checksum and is never verified (ADR 0014), even
// when a client names it in X-Amz-Trailer.
func TestChkTrailerSignatureIsNotAChecksum(t *testing.T) {
	payload := chkPayload(1024)
	framed := chkFramed(payload, 0, true, nil)

	p := chkParser(t)
	r := chkChunkedRequest(payload, framed, "x-amz-trailer-signature", true)
	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
}

// A header value and a trailer value for the same algorithm are both compared.
func TestChkHeaderAndTrailerForOneAlgorithm(t *testing.T) {
	payload := chkPayload(3000)
	alg := chkAlgorithms["crc32"]
	correct := chkEncode(alg.digest(payload))

	p := chkParser(t)
	framed := chkFramed(payload, 0, false, map[string]string{alg.trailer: correct})
	r := chkChunkedRequest(payload, framed, alg.trailer, false)
	r.Header.Set(alg.header, chkEncode(alg.digest([]byte("not the payload"))))

	if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("a wrong header value must fail even when the trailer is right: %v", err)
	}
}

// Two algorithms at once: each gets its own pass and both must hold.
func TestChkSeveralAlgorithmsAtOnce(t *testing.T) {
	payload := chkPayload(5000)
	crc := chkAlgorithms["crc32c"]
	sha := chkAlgorithms["sha256"]

	p := chkParser(t)
	r := chkIdentityRequest(payload)
	r.Header.Set(crc.header, chkEncode(crc.digest(payload)))
	r.Header.Set(sha.header, chkEncode(sha.digest(payload)))
	if _, err := p.ReadBody(r); err != nil {
		t.Fatalf("two correct declarations must both pass: %v", err)
	}

	r = chkIdentityRequest(payload)
	r.Header.Set(crc.header, chkEncode(crc.digest(payload)))
	r.Header.Set(sha.header, chkEncode(sha.digest([]byte("other"))))
	if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("one wrong declaration must fail the request: %v", err)
	}
}

// An empty body verifies against the digest of nothing.
func TestChkEmptyBody(t *testing.T) {
	alg := chkAlgorithms["md5"]
	p := chkParser(t)

	r := chkIdentityRequest(nil)
	r.Header.Set(alg.header, chkEncode(alg.digest(nil)))
	if _, err := p.ReadBody(r); err != nil {
		t.Fatalf("an empty body with a correct digest must pass: %v", err)
	}

	r = chkIdentityRequest(nil)
	r.Header.Set(alg.header, chkEncode(alg.digest([]byte("x"))))
	if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatal("an empty body with a wrong digest must fail")
	}
}

// The reader must be robust against the read sizes a consumer actually uses,
// including a one-byte buffer, which is where the held-back byte is tightest.
func TestChkSmallReadSizes(t *testing.T) {
	payload := chkPayload(257)
	alg := chkAlgorithms["sha256"]
	p := chkParser(t)

	for _, size := range []int{1, 2, 3, 64, 256, 4096} {
		r := chkIdentityRequest(payload)
		r.Header.Set(alg.header, chkEncode(alg.digest(payload)))
		src, err := p.StreamingReader(r)
		if err != nil {
			t.Fatal(err)
		}

		var out []byte
		buf := make([]byte, size)
		for {
			n, rerr := src.Read(buf)
			out = append(out, buf[:n]...)
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				t.Fatalf("read size %d: %v", size, rerr)
			}
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("read size %d: payload changed (%d bytes out of %d)", size, len(out), len(payload))
		}
	}
}

// The verdict must precede the last byte: a consumer that streams the body
// straight on can never hold the complete payload while verification is open
// (ADR 0012 D7). This is what stops a pass-through PUT from committing a body
// the backend has already received in full.
func TestChkTheLastByteIsHeldUntilTheVerdict(t *testing.T) {
	payload := chkPayload(1024)
	alg := chkAlgorithms["crc32"]
	p := chkParser(t)

	r := chkIdentityRequest(payload)
	r.Header.Set(alg.header, chkEncode(alg.digest([]byte("wrong"))))
	src, err := p.StreamingReader(r)
	if err != nil {
		t.Fatal(err)
	}

	var delivered int
	buf := make([]byte, 4096)
	for {
		n, rerr := src.Read(buf)
		delivered += n
		if rerr != nil {
			if !errors.Is(rerr, ErrChecksumMismatch) {
				t.Fatalf("read: %v", rerr)
			}
			break
		}
	}
	if delivered >= len(payload) {
		t.Fatalf("a failing body handed out %d of %d bytes; the last byte must stay behind",
			delivered, len(payload))
	}
}

// aws-chunked decoding is not configurable: the framing is always stripped, so
// what a checksum covers is always the payload. There is no configuration under
// which the proxy hashes chunk headers, which is what the removed
// clean_aws_signature_v4_chunked key made possible.
func TestChkAWSChunkedIsAlwaysDecoded(t *testing.T) {
	payload := chkPayload(1024)
	alg := chkAlgorithms["crc32"]
	framed := chkFramed(payload, 0, false, map[string]string{alg.trailer: chkEncode(alg.digest(payload))})

	// A parser built from a bare configuration, the way every caller builds one.
	p := NewParser(testLogger(), &config.Config{})

	got, err := p.ReadBody(chkChunkedRequest(payload, framed, alg.trailer, false))
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the payload is what comes back, never the framing")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks. The naive CRC-64/NVME form must not ship.
// ---------------------------------------------------------------------------

func BenchmarkChkCRC64NVME(b *testing.B) {
	block := make([]byte, 128*1024)

	b.Run("package_table", func(b *testing.B) {
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		h := newCRC64NVME()
		for i := 0; i < b.N; i++ {
			_, _ = h.Write(block)
		}
	})

	b.Run("naive_stdlib", func(b *testing.B) {
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		h := naiveCRC64NVME()
		for i := 0; i < b.N; i++ {
			_, _ = h.Write(block)
		}
	})
}

func BenchmarkChkVerifyingRead(b *testing.B) {
	payload := chkPayload(4 << 20)
	alg := chkAlgorithms["crc32"]
	value := chkEncode(alg.digest(payload))

	p := NewParser(testLogger(), &config.Config{})
	buf := make([]byte, 128*1024)

	for _, declared := range []bool{false, true} {
		name := "nothing_declared"
		if declared {
			name = "crc32_declared"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r := chkIdentityRequest(payload)
				if declared {
					r.Header.Set(alg.header, value)
				}
				src, err := p.StreamingReader(r)
				if err != nil {
					b.Fatal(err)
				}
				for {
					if _, rerr := src.Read(buf); rerr != nil {
						if rerr == io.EOF {
							break
						}
						b.Fatal(rerr)
					}
				}
			}
		})
	}
}

// BenchmarkChkAlgorithms is the per-algorithm cost table ADR 0012 D13 publishes:
// what a client pays on the proxy for the algorithm it chose. The CRCs run on
// dedicated instructions on both supported architectures, MD5 on none.
func BenchmarkChkAlgorithms(b *testing.B) {
	block := make([]byte, 128*1024)
	for name, alg := range chkAlgorithms {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(block)))
			h := checksumAlgorithms[chkKey(alg)].newHash()
			for i := 0; i < b.N; i++ {
				_, _ = h.Write(block)
			}
		})
	}
}

func chkKey(alg chkAlgorithm) string {
	if alg.trailer != "" {
		return alg.trailer
	}
	return "content-md5"
}

// ---------------------------------------------------------------------------
// Findings from the review round of 2026-09-11.
// ---------------------------------------------------------------------------

// S3 defines more upload checksum algorithms than this proxy computes: the
// pinned SDK serializes x-amz-checksum-xxhash3, -xxhash64 and -xxhash128, none
// of which has a standard-library hash. A declaration the proxy cannot verify is
// refused, never accepted and dropped (ADR 0007).
func TestChkUnimplementedAlgorithmIsRefused(t *testing.T) {
	for _, header := range []string{
		"x-amz-checksum-xxhash3", "x-amz-checksum-xxhash64", "x-amz-checksum-xxhash128",
		"x-amz-checksum-somethingnew",
	} {
		t.Run(header, func(t *testing.T) {
			p := chkParser(t)
			r := chkIdentityRequest(chkPayload(256))
			r.Header.Set(header, "AAAAAAAAAAAAAAAAAAAAAA==")

			if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumUnsupported) {
				t.Fatalf("error = %v, want ErrChecksumUnsupported", err)
			}
			if !DeclaresChecksum(r) {
				t.Fatal("the client did declare a digest, even one this proxy cannot check")
			}
		})
	}
}

// The three members of the family that select an algorithm or a mode carry no
// digest and must not be mistaken for one.
func TestChkChecksumControlHeadersAreNotRefused(t *testing.T) {
	p := chkParser(t)
	payload := chkPayload(256)
	r := chkIdentityRequest(payload)
	r.Header.Set("x-amz-checksum-algorithm", "CRC32")
	r.Header.Set("x-amz-checksum-mode", "ENABLED")
	r.Header.Set("x-amz-checksum-type", "FULL_OBJECT")

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
}

// SHA-512 and x-amz-checksum-md5 are both real upload declarations in the pinned
// SDK, and both are stdlib.
func TestChkSHA512AndAmzMD5AreVerified(t *testing.T) {
	payload := chkPayload(4096)
	for header, digest := range map[string]func([]byte) []byte{
		"x-amz-checksum-sha512": func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
		"x-amz-checksum-md5":    func(b []byte) []byte { s := md5.Sum(b); return s[:] }, // #nosec G401
	} {
		t.Run(header, func(t *testing.T) {
			p := chkParser(t)

			r := chkIdentityRequest(payload)
			r.Header.Set(header, chkEncode(digest(payload)))
			if _, err := p.ReadBody(r); err != nil {
				t.Fatalf("a correct %s must pass: %v", header, err)
			}

			r = chkIdentityRequest(payload)
			r.Header.Set(header, chkEncode(digest([]byte("other"))))
			if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumMismatch) {
				t.Fatalf("a wrong %s must fail: %v", header, err)
			}
		})
	}
}

// net/http keeps repeated headers as separate values, so a client naming two
// trailers in two X-Amz-Trailer lines must have both verified. Header.Get
// returns one of them and would drop the second without a word.
func TestChkRepeatedTrailerDeclarationHeaders(t *testing.T) {
	payload := chkPayload(4096)
	crc := chkAlgorithms["crc32c"]
	sha := chkAlgorithms["sha256"]

	build := func(shaValue string) *http.Request {
		framed := chkFramed(payload, 1024, false, map[string]string{
			crc.trailer: chkEncode(crc.digest(payload)),
			sha.trailer: shaValue,
		})
		r := chkChunkedRequest(payload, framed, "", false)
		r.Header.Add("X-Amz-Trailer", crc.trailer)
		r.Header.Add("X-Amz-Trailer", sha.trailer)
		return r
	}

	p := chkParser(t)
	if _, err := p.ReadBody(build(chkEncode(sha.digest(payload)))); err != nil {
		t.Fatalf("two correct trailers must both pass: %v", err)
	}
	if _, err := p.ReadBody(build(chkEncode(sha.digest([]byte("other"))))); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatal("the second declared trailer must be verified too")
	}
}

// The trailer block is kept now rather than drained, so it needs a ceiling: a
// client must not be able to spend the proxy's memory by sending one. Only
// checksum names are kept at all.
func TestChkTrailerBlockIsBounded(t *testing.T) {
	payload := chkPayload(1024)
	alg := chkAlgorithms["crc32"]

	var buf bytes.Buffer
	writeChunks(&buf, payload, 0, "")
	buf.WriteString("0\r\n")
	fmt.Fprintf(&buf, "%s:%s\r\n", alg.trailer, chkEncode(alg.digest(payload)))
	for i := 0; i < 50_000; i++ {
		fmt.Fprintf(&buf, "x-junk-%d:%s\r\n", i, strings.Repeat("A", 64))
	}
	buf.WriteString("\r\n")

	decoder := newStreamingAWSChunkedReader(io.NopCloser(bytes.NewReader(buf.Bytes())), testLogger())
	src, err := verifying(chkChunkedRequest(payload, buf.Bytes(), alg.trailer, false), decoder, decoder.Trailers)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(src)
	if err != nil {
		t.Fatalf("the declared trailer is the first line and must still verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
	if n := len(decoder.Trailers()); n > maxTrailerLines {
		t.Fatalf("kept %d trailers, the bound is %d", n, maxTrailerLines)
	}
	for name := range decoder.Trailers() {
		if !strings.HasPrefix(name, checksumHeaderPrefix) {
			t.Fatalf("kept a non-checksum trailer %q", name)
		}
	}
}

// CompleteMultipartUpload is the one verb where x-amz-checksum-* is the digest
// of the completed object rather than of the request document. Verifying it
// against the document would refuse a correct client.
func TestChkReadBodyUnverifiedSkipsTheCheck(t *testing.T) {
	p := chkParser(t)
	doc := []byte("<CompleteMultipartUpload></CompleteMultipartUpload>")

	r := chkIdentityRequest(doc)
	// A digest of the completed object, which is not this document.
	r.Header.Set("x-amz-checksum-crc32", chkEncode(chkAlgorithms["crc32"].digest([]byte("the object"))))

	got, err := p.ReadBodyUnverified(r)
	if err != nil {
		t.Fatalf("an object checksum must not be checked against the document: %v", err)
	}
	if !bytes.Equal(got, doc) {
		t.Fatal("document changed")
	}

	// The verifying entry point would refuse the same request, which is what
	// makes the distinction load-bearing.
	r = chkIdentityRequest(doc)
	r.Header.Set("x-amz-checksum-crc32", chkEncode(chkAlgorithms["crc32"].digest([]byte("the object"))))
	if _, err := p.ReadBody(r); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("ReadBody must still verify: %v", err)
	}
}
