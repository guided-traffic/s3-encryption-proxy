package s3enc

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/storedobject"
)

// PutOptions carries what a write stores besides the body.
type PutOptions struct {
	ContentType string
	// Metadata is stored as x-amz-meta-*. A key inside the metadata prefix is
	// refused with ErrReservedMetadata.
	Metadata map[string]string
}

// PutResult describes a completed write.
type PutResult struct {
	// ETag is the stored object's change token, not a digest of the plaintext.
	ETag string
	// Size is the plaintext length written.
	Size int64
	// CRC32C is the plaintext's CRC32C, base64 of the four big-endian bytes,
	// the way S3 states x-amz-checksum-crc32c. The same value is sealed into
	// the object's trailer, so Stat returns it later without a download.
	CRC32C string
}

// Put encrypts body and stores it under key. The body is streamed: it is read
// once, sealed segment by segment and uploaded in parts, so its length need not
// be known. A body that fails while being read stores nothing; a multipart
// upload is aborted.
func (c *Client) Put(ctx context.Context, bucket, key string, body io.Reader, opts *PutOptions) (*PutResult, error) {
	if opts == nil {
		opts = &PutOptions{}
	}
	if err := c.checkUserMetadata(opts.Metadata); err != nil {
		return nil, err
	}

	codec, md, err := storedobject.New(ctx, c.active, c.prefix, key, opts.Metadata)
	if err != nil {
		return nil, fmt.Errorf("s3enc: %w", err)
	}

	sealed := codec.NewEncryptReader(body)
	input := &transfermanager.UploadObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     sealed,
		Metadata: md,
	}
	if opts.ContentType != "" {
		input.ContentType = aws.String(opts.ContentType)
	}

	out, err := c.uploader.UploadObject(ctx, input)
	if err != nil {
		return nil, err
	}
	sum, _ := sealed.Checksum() // complete: the uploader has read the body to io.EOF
	return &PutResult{ETag: aws.ToString(out.ETag), Size: sum.Length, CRC32C: sum.Base64()}, nil
}

// Copy re-encrypts an object under a new key. A server-side CopyObject cannot
// do this: the object key is part of what every segment authenticates, so a
// copied object would fail to open. The data passes through this process once,
// streamed, under a fresh data key wrapped by the active key — so Copy also
// moves an object off a retired key. A source that fails authentication while
// it is read leaves no destination object behind.
func (c *Client) Copy(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (*PutResult, error) {
	src, err := c.Get(ctx, srcBucket, srcKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	return c.Put(ctx, dstBucket, dstKey, src, &PutOptions{ContentType: src.ContentType, Metadata: src.Metadata})
}
