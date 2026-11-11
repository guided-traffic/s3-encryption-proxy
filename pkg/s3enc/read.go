package s3enc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/storedobject"
)

// Object is the plaintext of a stored object, or of a range of it.
//
// Every byte Read returns has been authenticated. A whole-object read is
// complete and verified only when Read returns io.EOF: the trailer, which
// authenticates the length and the CRC32C, is checked at the end. If Read
// returns any other error, discard what was read.
type Object struct {
	// Size is how many plaintext bytes Read will deliver. It is derived from
	// the stored length the backend reports; the read fails with ErrCorrupt if
	// the stored data disagree with it.
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
	// Metadata is the caller's metadata, without the format's namespace.
	Metadata map[string]string

	plain io.Reader
	body  io.ReadCloser
}

// Read reads authenticated plaintext.
func (o *Object) Read(p []byte) (int, error) { return o.plain.Read(p) }

// Close releases the backend connection.
func (o *Object) Close() error { return o.body.Close() }

// Checksum returns the CRC32C the trailer authenticates, base64 as S3 states
// it. It is available only after a whole-object read has returned io.EOF.
func (o *Object) Checksum() (string, bool) {
	r, ok := o.plain.(interface {
		Checksum() (dataencryption.Checksum, bool)
	})
	if !ok {
		return "", false
	}
	sum, done := r.Checksum()
	if !done {
		return "", false
	}
	return sum.Base64(), true
}

// Info describes a stored object. Size and CRC32C come from the sealed
// trailer, so unlike S3's own Content-Length they are authenticated.
type Info struct {
	Size         int64
	CRC32C       string
	ETag         string
	ContentType  string
	LastModified time.Time
	Metadata     map[string]string
}

// Get opens a whole object for reading in one request.
func (c *Client) Get(ctx context.Context, bucket, key string) (*Object, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	codec, err := c.codecFor(ctx, key, out.Metadata)
	if err != nil {
		_ = out.Body.Close()
		return nil, err
	}
	size, err := dataencryption.PlaintextSize(aws.ToInt64(out.ContentLength))
	if err != nil {
		_ = out.Body.Close()
		return nil, ErrCorrupt
	}
	return &Object{
		Size:         size,
		ETag:         aws.ToString(out.ETag),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
		Metadata:     storedobject.UserMetadata(c.prefix, out.Metadata),
		plain:        codec.NewReader(out.Body),
		body:         out.Body,
	}, nil
}

// GetRange opens length plaintext bytes starting at offset. A length past the
// end is cut at the end. It costs a HEAD and one ranged GET of only the
// segments the range touches; the GET is pinned to the HEAD's entity tag, so an
// overwrite in between fails the read instead of splicing two objects.
func (c *Client) GetRange(ctx context.Context, bucket, key string, offset, length int64) (*Object, error) {
	head, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	codec, err := c.codecFor(ctx, key, head.Metadata)
	if err != nil {
		return nil, err
	}
	total, err := dataencryption.PlaintextSize(aws.ToInt64(head.ContentLength))
	if err != nil {
		return nil, ErrCorrupt
	}
	window, err := dataencryption.PlanRange(offset, length, total)
	if err != nil {
		return nil, err
	}

	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket:  aws.String(bucket),
		Key:     aws.String(key),
		IfMatch: head.ETag,
		Range: aws.String(fmt.Sprintf("bytes=%d-%d",
			window.CiphertextOffset, window.CiphertextOffset+window.CiphertextLength-1)),
	})
	if err != nil {
		return nil, err
	}
	return &Object{
		Size:         window.PlaintextLength,
		ETag:         aws.ToString(out.ETag),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
		Metadata:     storedobject.UserMetadata(c.prefix, head.Metadata),
		plain:        codec.NewRangeReader(out.Body, window),
		body:         out.Body,
	}, nil
}

// Stat reads the object's sealed trailer — the last 40 stored bytes — and
// returns the plaintext length and CRC32C it authenticates. One small ranged
// GET, no download: enough to tell whether a local file and a stored object
// hold the same content.
func (c *Client) Stat(ctx context.Context, bucket, key string) (*Info, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String(fmt.Sprintf("bytes=-%d", dataencryption.TrailerSize)),
	})
	if err != nil {
		// Only an empty object makes a suffix range unsatisfiable, and an empty
		// object cannot be one of this format: the trailer alone is 40 bytes.
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidRange" {
			return nil, ErrNotEncrypted
		}
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()

	codec, err := c.codecFor(ctx, key, out.Metadata)
	if err != nil {
		return nil, err
	}

	// A suffix range larger than the object comes back as the whole object,
	// with or without a Content-Range; both carry the stored total.
	storedTotal := aws.ToInt64(out.ContentLength)
	if cr := aws.ToString(out.ContentRange); cr != "" {
		if storedTotal, err = storedobject.TotalFromContentRange(cr); err != nil {
			return nil, err
		}
	}
	trailer := make([]byte, dataencryption.TrailerSize)
	if _, err := io.ReadFull(out.Body, trailer); err != nil {
		return nil, ErrCorrupt
	}
	// The trailer is the authenticated length; the stored length is the
	// backend's word, and OpenTrailer refuses the two disagreeing.
	sum, err := codec.OpenTrailer(trailer, storedTotal)
	if err != nil {
		return nil, err
	}

	return &Info{
		Size:         sum.Length,
		CRC32C:       sum.Base64(),
		ETag:         aws.ToString(out.ETag),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
		Metadata:     storedobject.UserMetadata(c.prefix, out.Metadata),
	}, nil
}

// PlaintextSize converts the size a listing reports into the plaintext size,
// without a key and without a request. It is the backend's number; only Stat
// authenticates it.
func PlaintextSize(storedSize int64) (int64, error) {
	return dataencryption.PlaintextSize(storedSize)
}
