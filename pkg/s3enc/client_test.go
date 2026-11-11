package s3enc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/storedobject"
)

func randomKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestNewRefusesWeakOrMalformedKeys(t *testing.T) {
	lowEntropy := bytes.Repeat([]byte{0x00, 0x01}, 16)
	cases := map[string]string{
		"not base64":      "not-base64!!",
		"16 bytes":        base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"passphrase":      base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		"two byte values": base64.StdEncoding.EncodeToString(lowEntropy),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(nil, Options{ActiveKey: key}); err == nil {
				t.Fatal("key accepted")
			}
			if _, err := New(nil, Options{ActiveKey: randomKey(t), RetiredKeys: []string{key}}); err == nil {
				t.Fatal("retired key accepted")
			}
		})
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	for _, prefix := range []string{"S3EP-", "s3ep", "ab-", "-abc-"} {
		if _, err := New(nil, Options{ActiveKey: randomKey(t), MetadataPrefix: prefix}); err == nil {
			t.Errorf("prefix %q accepted", prefix)
		}
	}
	if _, err := New(nil, Options{ActiveKey: randomKey(t), PartSize: 1 << 20}); err == nil {
		t.Error("part size below 5 MiB accepted")
	}
	if _, err := New(nil, Options{ActiveKey: randomKey(t), MetadataPrefix: "mycompany-enc-"}); err != nil {
		t.Errorf("valid prefix refused: %v", err)
	}
}

// TestKeyRing checks what a read needs from the metadata storedobject writes,
// without a backend: the key ring, and each refusal. The metadata rules
// themselves are storedobject's and tested there.
func TestKeyRing(t *testing.T) {
	ctx := context.Background()
	keyA, keyB := randomKey(t), randomKey(t)
	a, _ := New(nil, Options{ActiveKey: keyA})
	b, _ := New(nil, Options{ActiveKey: keyB})
	ba, _ := New(nil, Options{ActiveKey: keyB, RetiredKeys: []string{keyA}})

	sealer, md, err := storedobject.New(ctx, a.active, a.prefix, "dir/object", map[string]string{"owner": "glue"})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := io.ReadAll(sealer.NewEncryptReader(bytes.NewReader([]byte("hello"))))

	for name, c := range map[string]*Client{"writer": a, "retired key": ba} {
		codec, err := c.codecFor(ctx, "dir/object", md)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		plain, err := io.ReadAll(codec.NewReader(bytes.NewReader(stored)))
		if err != nil || string(plain) != "hello" {
			t.Fatalf("%s: read %q, %v", name, plain, err)
		}
	}

	// The object key is authenticated: the same bytes under another key fail.
	codec, _ := a.codecFor(ctx, "other/object", md)
	if _, err := io.ReadAll(codec.NewReader(bytes.NewReader(stored))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("moved object: err = %v, want ErrCorrupt", err)
	}

	if _, err := b.codecFor(ctx, "dir/object", md); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("foreign key: err = %v, want ErrUnknownKey", err)
	}

	noFormat := map[string]string{"owner": "glue"}
	if _, err := a.codecFor(ctx, "dir/object", noFormat); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("no format: err = %v, want ErrNotEncrypted", err)
	}

	for _, field := range []string{storedobject.KeyEncryptedDEK, storedobject.KeyKEKFingerprint} {
		damaged := maps.Clone(md)
		delete(damaged, a.prefix+field)
		if _, err := a.codecFor(ctx, "dir/object", damaged); !errors.Is(err, ErrKeyMaterialUnreadable) {
			t.Errorf("no %s: err = %v, want ErrKeyMaterialUnreadable", field, err)
		}
	}

	forged := maps.Clone(md)
	raw, _ := base64.StdEncoding.DecodeString(md["s3ep-encrypted-dek"])
	raw[len(raw)-1] ^= 0x01
	forged["s3ep-encrypted-dek"] = base64.StdEncoding.EncodeToString(raw)
	if _, err := a.codecFor(ctx, "dir/object", forged); !errors.Is(err, ErrKeyMaterialUnreadable) {
		t.Errorf("forged data key: err = %v, want ErrKeyMaterialUnreadable", err)
	}
}

func TestReservedUserMetadataIsRefused(t *testing.T) {
	c, _ := New(nil, Options{ActiveKey: randomKey(t)})
	for _, key := range []string{"s3ep-anything", "S3EP-Encrypted-DEK"} {
		if err := c.checkUserMetadata(map[string]string{key: "x"}); !errors.Is(err, ErrReservedMetadata) {
			t.Errorf("%q: err = %v, want ErrReservedMetadata", key, err)
		}
	}
}
