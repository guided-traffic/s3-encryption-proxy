//go:build conformance

package conformance

import (
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BucketCeilingBytes is what the whole prefix may hold. The corpus is about
// 10.3 MiB plus the segment overhead; anything approaching this ceiling means
// something is accumulating that nobody intended, and on a backend that bills a
// written byte for ninety days that is the failure worth catching early.
//
// It is asserted rather than logged because a warning in a scheduled run is a
// warning nobody reads.
const BucketCeilingBytes int64 = 32 << 20

// TestNoDanglingMultipartUploads is the cost guard that matters most.
//
// An incomplete multipart upload holds its parts as stored, billed data until it
// is aborted, and it does not appear in a listing — so it accumulates invisibly.
// Every test here aborts what it opens, and this asserts that they did.
func TestNoDanglingMultipartUploads(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	out, err := proxy.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(Bucket),
		Prefix: aws.String(KeyPrefix),
	})
	require.NoError(t, err)

	if len(out.Uploads) == 0 {
		return
	}

	for _, upload := range out.Uploads {
		t.Errorf("a multipart upload is open and its parts are billed: key=%s uploadId=%s initiated=%v",
			aws.ToString(upload.Key), aws.ToString(upload.UploadId), upload.Initiated)
	}
	t.Fatalf("%d multipart upload(s) left open under %s. Abort them: "+
		"on a backend with a ninety-day minimum their parts are charged whether or not "+
		"the object was ever completed.", len(out.Uploads), KeyPrefix)
}

// TestStoredFootprintIsUnderTheCeiling reads what the prefix actually holds and
// fails before it grows into real money.
//
// The listing reports plaintext sizes, so the stored footprint is larger than
// what this sums — that is deliberate. The ceiling is generous enough that the
// difference does not matter and tight enough that a runaway write trips it.
func TestStoredFootprintIsUnderTheCeiling(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	var total int64
	var objects int
	var token *string

	for {
		page, err := proxy.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(Bucket),
			Prefix:            aws.String(KeyPrefix),
			ContinuationToken: token,
		})
		require.NoError(t, err)
		for _, entry := range page.Contents {
			total += aws.ToInt64(entry.Size)
			objects++
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		token = page.NextContinuationToken
	}

	t.Logf("%s holds %d objects totalling %d plaintext bytes (%.2f MiB) under %s",
		BackendName, objects, total, float64(total)/(1<<20), KeyPrefix)

	assert.LessOrEqual(t, total, BucketCeilingBytes,
		"the conformance prefix has grown past its ceiling. Something is writing that should not: "+
			"every byte here is billed for ninety days and deleting it does not refund that.")
}

// TestRefusalsLeftNothingBehind checks the keys the refusal tests aim at. Each
// of them must be absent, because a refused write that stored anything would
// turn the cheapest part of this suite into a recurring charge.
func TestRefusalsLeftNothingBehind(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	out, err := proxy.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(Bucket),
		Prefix: aws.String(KeyPrefix + "refused/"),
	})
	require.NoError(t, err)

	for _, entry := range out.Contents {
		t.Errorf("a refused request stored %s (%d bytes) — a refusal must write nothing",
			aws.ToString(entry.Key), aws.ToInt64(entry.Size))
	}
	assert.Empty(t, out.Contents)
}

// TestAbortDanglingUploads removes what TestNoDanglingMultipartUploads reports.
//
// Opt-in through S3EP_CONFORMANCE_ABORT_DANGLING=1, for the same reason the seed
// is opt-in: aborting is irreversible, and a run that cleaned up by default could
// destroy an upload someone else had in flight against the same bucket. It is
// scoped to the suite's own key prefix and nothing else.
//
// It exists because the abort in a test's t.Cleanup can itself fail — that is
// exactly how the first three strays appeared here, from runs made before the
// credential was allowed to abort at all. A guard that can only report a leak it
// cannot clean sends someone to a web console.
func TestAbortDanglingUploads(t *testing.T) {
	if os.Getenv("S3EP_CONFORMANCE_ABORT_DANGLING") != "1" {
		t.Skip("set S3EP_CONFORMANCE_ABORT_DANGLING=1 to abort the uploads left under the suite's prefix")
	}

	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	out, err := proxy.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(Bucket),
		Prefix: aws.String(KeyPrefix),
	})
	require.NoError(t, err)

	if len(out.Uploads) == 0 {
		t.Logf("nothing to abort under %s", KeyPrefix)
		return
	}

	for _, upload := range out.Uploads {
		key := aws.ToString(upload.Key)
		// Belt and braces: the listing was already filtered by prefix, and an
		// abort is irreversible, so the key is checked again before the call.
		require.True(t, strings.HasPrefix(key, KeyPrefix),
			"refusing to abort %s: it is outside the suite's prefix %s", key, KeyPrefix)

		_, abortErr := proxy.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(Bucket),
			Key:      aws.String(key),
			UploadId: upload.UploadId,
		})
		if abortErr != nil {
			t.Errorf("aborting %s (%s): %v", key, aws.ToString(upload.UploadId), abortErr)
			continue
		}
		t.Logf("aborted: %s initiated=%v", key, upload.Initiated)
	}
}
