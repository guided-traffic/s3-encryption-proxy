package bucket

import (
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The entity-tag marker in a listing (ADR 0032 D3).
//
// A listing is where the marker has to work and where nothing else can: a
// listing entry carries no metadata and ADR 0010 D2 forbids a per-object
// request, so a value stored on the object - in metadata or sealed inside it -
// is unreachable here. The marker is derived from the tag the listing already
// carries, which is why it costs nothing.
//
// The listing fixtures elsewhere in this package use "ciphertext-etag", a name
// the marker never fires against. These carry a real digest.
// ---------------------------------------------------------------------------

const (
	BktTagDigest = `"2c52a8e3b689c5ea7f55444e2000b35a"`
	BktTagMarked = `2c52a8e3b689c5ea7f55444e2000b35a-0`
)

// Both listing versions mark, and they mark the same way the object verbs do:
// a listing that disagreed with a HEAD of the same object would be worse than
// either answer on its own.
func TestBktTagBothListingsMarkADigestShapedTag(t *testing.T) {
	modified := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	t.Run("V2", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			KeyCount: aws.Int32(1),
			MaxKeys:  aws.Int32(1000),
			Contents: []s3types.Object{{
				Key:          aws.String("k"),
				Size:         aws.Int64(1_048_604),
				LastModified: &modified,
				ETag:         aws.String(BktTagDigest),
			}},
		})
		h := BktnewHandlerWithProvider(t, backend, "aes")

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<ETag>&#34;"+BktTagMarked+"&#34;</ETag>")
	})

	t.Run("V1", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV1(backend, &s3.ListObjectsOutput{
			Name:    aws.String(bktBucket),
			MaxKeys: aws.Int32(1000),
			Contents: []s3types.Object{{
				Key:          aws.String("k"),
				Size:         aws.Int64(1_048_604),
				LastModified: &modified,
				ETag:         aws.String(BktTagDigest),
			}},
		})
		h := BktnewHandlerWithProvider(t, backend, "aes")

		w := BktauthGet(h, "/"+bktBucket)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<ETag>&#34;"+BktTagMarked+"&#34;</ETag>")
	})
}

// A tag that already says it is not a digest is left alone, in a listing as
// everywhere else.
func TestBktTagAMultipartTagInAListingIsNotMarked(t *testing.T) {
	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:     aws.String(bktBucket),
		KeyCount: aws.Int32(1),
		MaxKeys:  aws.Int32(1000),
		Contents: []s3types.Object{{
			Key:  aws.String("k"),
			Size: aws.Int64(1_048_604),
			ETag: aws.String(`"2c52a8e3b689c5ea7f55444e2000b35a-3"`),
		}},
	})
	h := BktnewHandlerWithProvider(t, backend, "aes")

	w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<ETag>&#34;2c52a8e3b689c5ea7f55444e2000b35a-3&#34;</ETag>")
}

// Under the exit provider the stored bytes are the plaintext, so the backend's
// tag is the truth about them and the listing states it unchanged - the same
// rule its sizes follow (ADR 0032 D7, ADR 0025).
func TestBktTagTheExitProviderListingIsUnmarked(t *testing.T) {
	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:     aws.String(bktBucket),
		KeyCount: aws.Int32(1),
		MaxKeys:  aws.Int32(1000),
		Contents: []s3types.Object{{
			Key:  aws.String("k"),
			Size: aws.Int64(1024),
			ETag: aws.String(BktTagDigest),
		}},
	})
	h := BktnewHandlerWithProvider(t, backend, "exit")

	w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<ETag>&#34;2c52a8e3b689c5ea7f55444e2000b35a&#34;</ETag>")
	assert.NotContains(t, w.Body.String(), "-0&#34;</ETag>")
}
