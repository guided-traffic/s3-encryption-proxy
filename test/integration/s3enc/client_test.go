//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc"
)

const (
	seg    = dataencryption.SegmentSize
	stride = dataencryption.SegmentSize + dataencryption.SegmentOverhead
)

// Sizes around every boundary the format has, plus one above the part size so
// the upload goes multipart.
var sizes = []int64{0, 1, seg - 1, seg, seg + 1, 3*seg + 5, 13<<20 + 3}

func TestRoundTrip(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})

	for _, n := range sizes {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key := objectKey(t, "file.bin")
			plain := randomBytes(t, n)

			res, err := c.Put(ctx, s.bucket, key, unknownLength{bytes.NewReader(plain)},
				&s3enc.PutOptions{ContentType: "application/x-test", Metadata: map[string]string{"owner": "library"}})
			if err != nil {
				t.Fatal(err)
			}
			if res.Size != n || res.CRC32C != crc32cBase64(plain) {
				t.Fatalf("put result = %+v, want size %d crc %s", res, n, crc32cBase64(plain))
			}

			// At rest: the format's length, the four keys, no plaintext.
			stored, md := s.rawGet(t, key)
			want, _ := dataencryption.CiphertextSize(n)
			if int64(len(stored)) != want {
				t.Fatalf("stored %d bytes, want %d", len(stored), want)
			}
			if formatKeys(md) != 4 || md["owner"] != "library" {
				t.Fatalf("stored metadata = %v", md)
			}
			if n >= 32 && bytes.Contains(stored, plain[:32]) {
				t.Fatal("plaintext found in stored bytes")
			}

			info, err := c.Stat(ctx, s.bucket, key)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size != n || info.CRC32C != res.CRC32C || info.Metadata["owner"] != "library" {
				t.Fatalf("stat = %+v", info)
			}

			obj, err := c.Get(ctx, s.bucket, key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readObject(obj)
			if err != nil {
				t.Fatal(err)
			}
			if digest(got) != digest(plain) || obj.Size != n {
				t.Fatalf("read %d bytes sha %s, want %d bytes sha %s", len(got), digest(got), n, digest(plain))
			}
			if sum, ok := obj.Checksum(); !ok || sum != res.CRC32C {
				t.Fatalf("checksum after EOF = %q %v, want %q", sum, ok, res.CRC32C)
			}
			if obj.ContentType != "application/x-test" || len(obj.Metadata) != 1 || obj.Metadata["owner"] != "library" {
				t.Fatalf("content type %q, metadata %v", obj.ContentType, obj.Metadata)
			}
		})
	}
}

func TestGetRange(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})
	n := int64(3*seg + 5)
	plain := randomBytes(t, n)
	key := objectKey(t, "ranged.bin")
	if _, err := c.Put(ctx, s.bucket, key, bytes.NewReader(plain), nil); err != nil {
		t.Fatal(err)
	}

	for _, r := range []struct{ off, length int64 }{
		{0, 1}, {seg - 1, 2}, {seg, seg}, {100, 1 << 30}, {n - 1, 1}, {0, n}, {2*seg + 7, seg},
	} {
		t.Run(fmt.Sprintf("%d+%d", r.off, r.length), func(t *testing.T) {
			obj, err := c.GetRange(ctx, s.bucket, key, r.off, r.length)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readObject(obj)
			if err != nil {
				t.Fatal(err)
			}
			want := plain[r.off:min(r.off+r.length, n)]
			if digest(got) != digest(want) || obj.Size != int64(len(want)) {
				t.Fatalf("read %d bytes, want %d", len(got), len(want))
			}
		})
	}

	if _, err := c.GetRange(ctx, s.bucket, key, n, 1); !errors.Is(err, s3enc.ErrRangeNotSatisfiable) {
		t.Fatalf("range past the end: err = %v", err)
	}
}

// TestTamperingIsRefused plays the hostile backend: it changes stored bytes
// directly in the storage and expects every read path to refuse them.
func TestTamperingIsRefused(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})
	n := int64(3*seg + 5)
	plain := randomBytes(t, n)

	put := func(t *testing.T) (string, []byte, map[string]string) {
		key := objectKey(t, "victim.bin")
		if _, err := c.Put(ctx, s.bucket, key, bytes.NewReader(plain), nil); err != nil {
			t.Fatal(err)
		}
		stored, md := s.rawGet(t, key)
		return key, stored, md
	}

	t.Run("flipped byte in segment 1", func(t *testing.T) {
		key, stored, md := put(t)
		stored[stride+100] ^= 0x01
		s.rawPut(t, key, stored, md)

		obj, err := c.Get(ctx, s.bucket, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readObject(obj); !errors.Is(err, s3enc.ErrCorrupt) {
			t.Fatalf("get: err = %v, want ErrCorrupt", err)
		}
		obj, err = c.GetRange(ctx, s.bucket, key, seg+10, 10)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readObject(obj); !errors.Is(err, s3enc.ErrCorrupt) {
			t.Fatalf("range over segment 1: err = %v, want ErrCorrupt", err)
		}
		// Segments are authenticated one by one: a range that does not touch the
		// damaged segment is still served.
		obj, err = c.GetRange(ctx, s.bucket, key, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := readObject(obj); err != nil || digest(got) != digest(plain[:10]) {
			t.Fatalf("range over segment 0: err = %v", err)
		}
	})

	t.Run("segment removed", func(t *testing.T) {
		key, stored, md := put(t)
		truncated := append(append([]byte{}, stored[:2*stride]...), stored[3*stride:]...)
		s.rawPut(t, key, truncated, md)

		if _, err := c.Stat(ctx, s.bucket, key); !errors.Is(err, s3enc.ErrCorrupt) {
			t.Fatalf("stat: err = %v, want ErrCorrupt", err)
		}
		obj, err := c.Get(ctx, s.bucket, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readObject(obj); !errors.Is(err, s3enc.ErrCorrupt) {
			t.Fatalf("get: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("server-side copy to another key", func(t *testing.T) {
		key, _, _ := put(t)
		moved := objectKey(t, "moved.bin")
		_, err := s.backend.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: aws.String(s.bucket), Key: aws.String(moved),
			CopySource: aws.String(s.bucket + "/" + key),
		})
		if err != nil {
			t.Fatal(err)
		}
		obj, err := c.Get(ctx, s.bucket, moved)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readObject(obj); !errors.Is(err, s3enc.ErrCorrupt) {
			t.Fatalf("copied object: err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("forged wrapped data key", func(t *testing.T) {
		key, stored, md := put(t)
		raw, _ := base64.StdEncoding.DecodeString(md["s3ep-encrypted-dek"])
		raw[len(raw)-1] ^= 0x01
		md["s3ep-encrypted-dek"] = base64.StdEncoding.EncodeToString(raw)
		s.rawPut(t, key, stored, md)

		if _, err := c.Get(ctx, s.bucket, key); !errors.Is(err, s3enc.ErrKeyMaterialUnreadable) {
			t.Fatalf("get: err = %v, want ErrKeyMaterialUnreadable", err)
		}
	})
}

func TestForeignObjectIsRefused(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})

	for name, body := range map[string][]byte{"plain": []byte("not encrypted, never to be served"), "empty": nil} {
		t.Run(name, func(t *testing.T) {
			key := objectKey(t, "foreign.txt")
			s.rawPut(t, key, body, nil)

			if _, err := c.Get(ctx, s.bucket, key); !errors.Is(err, s3enc.ErrNotEncrypted) {
				t.Errorf("get: err = %v", err)
			}
			if _, err := c.Stat(ctx, s.bucket, key); !errors.Is(err, s3enc.ErrNotEncrypted) {
				t.Errorf("stat: err = %v", err)
			}
			if _, err := c.GetRange(ctx, s.bucket, key, 0, 4); !errors.Is(err, s3enc.ErrNotEncrypted) {
				t.Errorf("range: err = %v", err)
			}
		})
	}
}

func TestKeyRotation(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	oldKey, newKey := randomKey(t), randomKey(t)
	before := s.client(t, s3enc.Options{ActiveKey: oldKey})
	strangers := s.client(t, s3enc.Options{ActiveKey: newKey})
	after := s.client(t, s3enc.Options{ActiveKey: newKey, RetiredKeys: []string{oldKey}})

	plain := randomBytes(t, 2*seg+9)
	key := objectKey(t, "old.bin")
	if _, err := before.Put(ctx, s.bucket, key, bytes.NewReader(plain), nil); err != nil {
		t.Fatal(err)
	}

	if _, err := strangers.Get(ctx, s.bucket, key); !errors.Is(err, s3enc.ErrUnknownKey) {
		t.Fatalf("without the old key: err = %v, want ErrUnknownKey", err)
	}

	obj, err := after.Get(ctx, s.bucket, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readObject(obj); err != nil || digest(got) != digest(plain) {
		t.Fatalf("with the old key retired: err = %v", err)
	}

	// Copy moves the object onto the active key.
	rotated := objectKey(t, "rotated.bin")
	if _, err := after.Copy(ctx, s.bucket, key, s.bucket, rotated); err != nil {
		t.Fatal(err)
	}
	obj, err = strangers.Get(ctx, s.bucket, rotated)
	if err != nil {
		t.Fatalf("rotated object needs no retired key: %v", err)
	}
	if got, err := readObject(obj); err != nil || digest(got) != digest(plain) {
		t.Fatalf("rotated object: err = %v", err)
	}
}

// TestCopyOfCorruptSourceStoresNothing: the read fails at the damaged segment,
// and the upload must fail with it rather than store what came before.
func TestCopyOfCorruptSourceStoresNothing(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})

	for _, n := range []int64{3*seg + 5, 13<<20 + 3} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key := objectKey(t, "src.bin")
			if _, err := c.Put(ctx, s.bucket, key, bytes.NewReader(randomBytes(t, n)), nil); err != nil {
				t.Fatal(err)
			}
			stored, md := s.rawGet(t, key)
			stored[len(stored)-dataencryption.TrailerSize-10] ^= 0x01 // inside the last segment
			s.rawPut(t, key, stored, md)

			dst := objectKey(t, "dst.bin")
			if _, err := c.Copy(ctx, s.bucket, key, s.bucket, dst); !errors.Is(err, s3enc.ErrCorrupt) {
				t.Fatalf("copy: err = %v, want ErrCorrupt", err)
			}
			if s.exists(t, dst) {
				t.Fatal("a corrupt source left a destination object")
			}
			uploads, err := s.backend.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket: aws.String(s.bucket), Prefix: aws.String(dst),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(uploads.Uploads) != 0 {
				t.Fatalf("%d multipart uploads left open", len(uploads.Uploads))
			}
		})
	}
}

func TestReservedMetadataStoresNothing(t *testing.T) {
	s := newStack(t)
	c := s.client(t, s3enc.Options{ActiveKey: randomKey(t)})
	key := objectKey(t, "reserved.bin")
	_, err := c.Put(s.ctx, s.bucket, key, bytes.NewReader([]byte("x")),
		&s3enc.PutOptions{Metadata: map[string]string{"S3EP-KEK-Fingerprint": "forged"}})
	if !errors.Is(err, s3enc.ErrReservedMetadata) {
		t.Fatalf("err = %v, want ErrReservedMetadata", err)
	}
	if s.exists(t, key) {
		t.Fatal("object stored")
	}
}
