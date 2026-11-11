// Package s3enc stores objects in S3 in the proxy's storage format without the
// proxy in between: an AES-256-GCM segment chain closed by a sealed trailer,
// under one random data key per object, wrapped by an AES-256 key encryption
// key (ADR 0041).
//
// It writes exactly what the proxy writes, through the same codec, the same key
// wrap and the same metadata rules, so an object stored through this package is
// readable through the proxy and the other way round, as long as both use the
// same key and the same metadata prefix.
//
// What the format guarantees, and what a caller of this package must do for it:
//
//   - Every segment is authenticated under associated data that binds the
//     format id, the object key and the segment index. A tampered, reordered or
//     moved segment fails with ErrCorrupt before a byte of it is handed out.
//   - The trailer authenticates the plaintext length and its CRC32C. A
//     whole-object read checks it when the body ends, so an object is only
//     verified once Read has returned io.EOF. Treat any other error at the end
//     as "discard everything read so far".
//   - The object key is part of the authenticated data. A server-side copy or
//     rename makes an object unreadable; use Copy, which re-encrypts.
//   - An object without this format's metadata is refused with ErrNotEncrypted.
//     There is no pass-through: this package never hands out stored bytes.
package s3enc

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/keyencryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/storedobject"
)

const (
	// DefaultMetadataPrefix is the proxy's default encryption.metadata_key_prefix.
	DefaultMetadataPrefix = storedobject.DefaultPrefix

	// DefaultPartSize is the proxy's default multipart_part_size. A body of
	// unknown length can be at most PartSize × 10,000 parts long (about 117 GiB
	// at the default); raise it for larger streams. It does not affect the
	// stored format: parts are cut from the ciphertext stream.
	DefaultPartSize = 12 << 20

	// DefaultConcurrency is the number of parts uploaded in parallel. Memory per
	// upload is about PartSize × Concurrency.
	DefaultConcurrency = 4

	minPartSize = 5 << 20 // the S3 minimum for every part but the last
)

var (
	// ErrNotEncrypted marks an object that carries no metadata of this format:
	// neither the proxy nor this package wrote it. Its bytes are never handed out.
	ErrNotEncrypted = errors.New("s3enc: object is not stored in the " + dataencryption.FormatID + " format")

	// ErrUnknownKey marks an object wrapped by a key fingerprint that none of the
	// configured keys carries. Add the key that wrote it to Options.RetiredKeys.
	ErrUnknownKey = errors.New("s3enc: object is wrapped by a key this client does not hold")

	// ErrKeyMaterialUnreadable marks an object whose wrapped data key is missing
	// or does not authenticate under the key it names. It is permanent; a retry
	// will not change it.
	ErrKeyMaterialUnreadable = errors.New("s3enc: wrapped data key is missing or does not authenticate")

	// ErrCorrupt marks stored bytes that fail authentication: tampered,
	// truncated, extended or reordered.
	ErrCorrupt = dataencryption.ErrCorrupt

	// ErrRangeNotSatisfiable marks a range that starts at or after the end of
	// the object.
	ErrRangeNotSatisfiable = dataencryption.ErrRangeNotSatisfiable

	// ErrReservedMetadata marks a user metadata key inside the metadata prefix,
	// which belongs to the format alone.
	ErrReservedMetadata = errors.New("s3enc: user metadata key lies inside the encryption metadata prefix")
)

// API is the part of *s3.Client this package uses. *s3.Client satisfies it.
type API = transfermanager.S3APIClient

// Options configures a Client.
type Options struct {
	// ActiveKey wraps the data key of every object this client writes: base64 of
	// exactly 32 random bytes, the same value as the proxy's aes_key. Generate it
	// with s3ep-keygen or `openssl rand -base64 32`.
	ActiveKey string

	// RetiredKeys still open the objects they wrapped and write nothing.
	RetiredKeys []string

	// MetadataPrefix must equal the proxy's encryption.metadata_key_prefix.
	// Empty means DefaultMetadataPrefix.
	MetadataPrefix string

	// PartSize and Concurrency tune uploads. Zero means the default.
	PartSize    int64
	Concurrency int
}

// Client reads and writes encrypted objects.
type Client struct {
	s3       API
	uploader *transfermanager.Client
	active   encryption.KeyEncryptor
	keys     map[string]encryption.KeyEncryptor // by fingerprint
	prefix   string
}

// New builds a Client on top of an S3 client.
func New(api API, opts Options) (*Client, error) {
	prefix := opts.MetadataPrefix
	if prefix == "" {
		prefix = DefaultMetadataPrefix
	}
	if !storedobject.PrefixPattern.MatchString(prefix) {
		return nil, fmt.Errorf("s3enc: metadata prefix %q must match %s", prefix, storedobject.PrefixPattern)
	}

	active, err := parseKey(opts.ActiveKey)
	if err != nil {
		return nil, fmt.Errorf("s3enc: active key: %w", err)
	}
	keys := map[string]encryption.KeyEncryptor{active.Fingerprint(): active}
	for i, k := range opts.RetiredKeys {
		kek, err := parseKey(k)
		if err != nil {
			return nil, fmt.Errorf("s3enc: retired key %d: %w", i, err)
		}
		keys[kek.Fingerprint()] = kek
	}

	partSize := opts.PartSize
	if partSize == 0 {
		partSize = DefaultPartSize
	}
	if partSize < minPartSize {
		return nil, fmt.Errorf("s3enc: part size %d is below the S3 minimum of %d", partSize, minPartSize)
	}
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = DefaultConcurrency
	}

	uploader := transfermanager.New(api, func(o *transfermanager.Options) {
		o.PartSizeBytes = partSize
		o.Concurrency = concurrency
		// The body is the ciphertext stream, produced as the uploader reads it
		// and not seekable. An opportunistic request checksum over it fails
		// outright against a plain-HTTP endpoint and costs a full extra pass
		// over every byte against an HTTPS one, and it would cover nothing the
		// format does not: every segment is authenticated, so a byte changed on
		// the way fails the read (ADR 0003). The proxy drops the same checksum
		// on its backend leg for the same reason.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	})

	return &Client{s3: api, uploader: uploader, active: active, keys: keys, prefix: prefix}, nil
}

// parseKey applies the proxy's own key rules: the same function decides for the
// proxy's configuration, so a key one accepts the other cannot refuse.
func parseKey(b64 string) (encryption.KeyEncryptor, error) {
	raw, err := keyencryption.DecodeAESKey(b64)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return keyencryption.NewAESKeyEncryptor(raw)
}

// checkUserMetadata refuses a caller key inside the prefix rather than dropping
// it, so a write never silently stores less than it was given.
func (c *Client) checkUserMetadata(user map[string]string) error {
	for k := range user {
		if storedobject.IsReserved(c.prefix, k) {
			return fmt.Errorf("%w: %q", ErrReservedMetadata, k)
		}
	}
	return nil
}

// codecFor unwraps an object's data key and binds it to the object key. The
// key encryption key is chosen by the fingerprint the object names, so a
// retired key still opens what it wrote.
func (c *Client) codecFor(ctx context.Context, objectKey string, md map[string]string) (*dataencryption.Codec, error) {
	if !storedobject.ClaimsFormat(c.prefix, md) {
		return nil, ErrNotEncrypted
	}
	// From here on the object claims this format, so anything missing is a
	// damaged object, not a foreign one.
	wrapped, err := storedobject.WrappedDEK(c.prefix, md)
	if err != nil {
		return nil, ErrKeyMaterialUnreadable
	}
	fingerprint, err := storedobject.Fingerprint(c.prefix, md)
	if err != nil {
		return nil, ErrKeyMaterialUnreadable
	}
	kek, ok := c.keys[fingerprint]
	if !ok {
		return nil, ErrUnknownKey
	}
	dek, err := kek.DecryptDEK(ctx, wrapped)
	if err != nil {
		if errors.Is(err, keyencryption.ErrWrappedDEKAuth) {
			return nil, ErrKeyMaterialUnreadable
		}
		return nil, err
	}
	defer clear(dek) // aes.NewCipher has expanded it into its own schedule
	return dataencryption.NewCodec(dek, objectKey)
}
