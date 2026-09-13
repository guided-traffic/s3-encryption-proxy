package multipart

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The entity-tag marker on the multipart paths (ADR 0032).
//
// Part level is not decoration: a client that drives its own multipart upload
// judges the answer part by part and never sees an object-level tag, so a marker
// that stops at the object leaves such a client unable to upload at all
// (ADR 0032 D3). The fixtures here carry a real thirty-two-hex digest, because
// every other entity-tag fixture in this package is a name and the marker never
// fires against one.
// ---------------------------------------------------------------------------

const (
	MpuTagPartDigest   = `"58d6a6131ee4337c8877716b2af05a6d"`
	MpuTagPartMarked   = `"58d6a6131ee4337c8877716b2af05a6d-0"`
	MpuTagObjectDigest = `"2c52a8e3b689c5ea7f55444e2000b35a"`
	MpuTagObjectMarked = `"2c52a8e3b689c5ea7f55444e2000b35a-0"`
)

// MpuTagacceptParts takes every part at the backend and answers a digest-shaped
// entity tag, which is what a real backend does for a part it stored.
func MpuTagacceptParts(e *MpuEnv) {
	e.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(MpuTagPartDigest)}, nil)
}

// A part the backend stored is answered with the marker; the part the proxy
// holds for Complete answers the proxy's own tag, which was never digest-shaped
// and is left exactly as it is.
func TestMpuTagPartUploadsAnswerTheMarker(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	MpuTagacceptParts(env)

	stored := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart))
	require.Equal(t, http.StatusOK, stored.Code, stored.Body.String())
	assert.Equal(t, MpuTagPartMarked, stored.Header().Get("ETag"),
		"a client judging a part by its entity tag must not read it as a digest of its own bytes")

	held := env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(1024))
	require.Equal(t, http.StatusOK, held.Code, held.Body.String())
	answered := held.Header().Get("ETag")
	assert.NotEqual(t, MpuTagPartMarked, answered)
	assert.Contains(t, answered, "-", "the held part already says it is not a digest")
	assert.NotRegexp(t, `^"[0-9a-f]{32}"$`, answered)
}

// The round trip the marker lives or dies by: the client sends back the part
// tags it was answered, marker and all, and the completion has to accept them
// (ADR 0032 D4). Without the inverse this is a 400 InvalidPart on every
// client-driven multipart upload.
func TestMpuTagAClientReturnsTheMarkedPartTagsAndCompletes(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	// MpuTagacceptParts and not MpuCaptureParts: the shared capture answers a
	// part tag that is a name, and the marker never fires against one.
	MpuTagacceptParts(env)

	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(MpuStorablePart)).Code)

	// What the client replays is what it was given, which is the marked tag.
	body := env.MpuCompleteBody(1, 2)
	require.Contains(t, body, "-0", "the fixture must replay the marked tags, or this proves nothing")

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(MpuTagObjectDigest)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1, 2)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, MpuTagObjectMarked, w.Header().Get("ETag"))

	var doc struct {
		XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
		ETag    string   `xml:"ETag"`
	}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, MpuTagObjectMarked, doc.ETag,
		"the document and the header state one entity tag")
}

// ListParts is answered from the proxy's own part table, and it answers the same
// tags the part uploads did.
func TestMpuTagListPartsAnswersTheMarker(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	// MpuTagacceptParts and not MpuCaptureParts: the shared capture answers a
	// part tag that is a name, and the marker never fires against one.
	MpuTagacceptParts(env)

	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(MpuStorablePart)).Code)

	url := fmt.Sprintf("/%s/%s?uploadId=%s", MpuBucket, MpuKey, MpuUploadID)
	w := httptest.NewRecorder()
	env.list().HandleListParts(w, MpuVars(httptest.NewRequest(http.MethodGet, url, nil)))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var doc MpuListPartsDoc
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc))
	require.Len(t, doc.Parts, 1)
	assert.Equal(t, MpuTagPartMarked, doc.Parts[0].ETag,
		"a listing of parts must agree with what each part upload answered")
}

// Under the exit provider the stored bytes are the client's own, so the
// backend's entity tag is the truth about them: nothing is marked, and the part
// list the client sends is the part identity the backend is given, untouched
// (ADR 0032 D7).
func TestMpuTagExitProviderMarksNothingAndForwardsTheList(t *testing.T) {
	env := MpuNewExitEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	MpuTagacceptParts(env)

	part := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(1024))
	require.Equal(t, http.StatusOK, part.Code, part.Body.String())
	assert.Equal(t, MpuTagPartDigest, part.Header().Get("ETag"))

	var forwarded []types.CompletedPart
	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(1).(*s3.CompleteMultipartUploadInput)
			forwarded = in.MultipartUpload.Parts
		}).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(MpuTagObjectDigest)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, MpuTagObjectDigest, w.Header().Get("ETag"), "nothing is marked under the exit provider")
	require.Len(t, forwarded, 1)
	assert.Equal(t, strings.Trim(MpuTagPartDigest, `"`), aws.ToString(forwarded[0].ETag),
		"the client's part identity reaches the backend exactly as the client stated it")
}
