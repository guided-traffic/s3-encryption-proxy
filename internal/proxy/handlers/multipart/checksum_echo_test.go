package multipart

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// x-amz-checksum-crc32c on the multipart write paths (ADR 0003 D16).
//
// A part's answer describes that part; the completion's answer describes the
// object. Both values are sealed into the upload anyway - the part checksums are
// what the trailer is folded from - so the cost is the header.
//
// Expectations are computed with the standard library, never with the codec's
// own helper.
// ---------------------------------------------------------------------------

// MpuCrcwant is what S3 states for a CRC32C over these bytes.
func MpuCrcwant(plaintext []byte) string {
	sum := crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli))
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], sum)
	return base64.StdEncoding.EncodeToString(raw[:])
}

// Every part answers its own checksum, and the short last part - which the proxy
// holds rather than stores - answers one too. A client that checks its parts one
// by one must get an answer for each, or the one it does not get is the one it
// stops checking.
func TestMpuCrcEveryPartAnswersItsOwnChecksum(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	// Two full parts, because only the last part of an upload may be short - and
	// two parts of the same length that differ in one byte, so the checksums
	// must differ for a reason the part size cannot explain.
	first := MpuPayload(MpuStorablePart)
	second := append([]byte(nil), first...)
	second[0] ^= 0xff
	short := MpuPayload(1024)

	one := env.MpuUploadPart(t, MpuUploadID, 1, first)
	require.Equal(t, http.StatusOK, one.Code, one.Body.String())
	assert.Equal(t, MpuCrcwant(first), one.Header().Get("x-amz-checksum-crc32c"))

	two := env.MpuUploadPart(t, MpuUploadID, 2, second)
	require.Equal(t, http.StatusOK, two.Code, two.Body.String())
	assert.Equal(t, MpuCrcwant(second), two.Header().Get("x-amz-checksum-crc32c"))

	held := env.MpuUploadPart(t, MpuUploadID, 3, short)
	require.Equal(t, http.StatusOK, held.Code, held.Body.String())
	assert.Equal(t, MpuCrcwant(short), held.Header().Get("x-amz-checksum-crc32c"),
		"a part the proxy holds is still a part the client uploaded")

	assert.NotEqual(t, one.Header().Get("x-amz-checksum-crc32c"), two.Header().Get("x-amz-checksum-crc32c"),
		"a part's checksum describes that part and nothing else")
}

// The same part number uploaded twice with different bytes answers two different
// values: the table is updated, not appended to.
func TestMpuCrcAReplacedPartAnswersTheNewChecksum(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	original := MpuPayload(MpuStorablePart)
	replacement := MpuPayload(MpuStorablePart / 4)

	before := env.MpuUploadPart(t, MpuUploadID, 1, original)
	require.Equal(t, http.StatusOK, before.Code)

	after := env.MpuUploadPart(t, MpuUploadID, 1, replacement)
	require.Equal(t, http.StatusOK, after.Code, after.Body.String())

	assert.Equal(t, MpuCrcwant(replacement), after.Header().Get("x-amz-checksum-crc32c"))
	assert.NotEqual(t, before.Header().Get("x-amz-checksum-crc32c"),
		after.Header().Get("x-amz-checksum-crc32c"))
}

// The completion answers the object's checksum: the CRC32C over every part's
// plaintext in order, which is exactly the value sealed into the trailer. A
// client that hashed the file it uploaded can compare against this one number.
func TestMpuCrcTheCompletionAnswersTheWholeObjectChecksum(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	first := MpuPayload(MpuStorablePart)
	second := MpuPayload(MpuStorablePart)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, first).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, second).Code)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1, 2)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, MpuCrcwant(append(append([]byte(nil), first...), second...)),
		w.Header().Get("x-amz-checksum-crc32c"),
		"the object is its parts in order, and so is its checksum")
}

// A held short part rides the completion, and the object's checksum has to cover
// it: this is the arm where the trailer is sealed together with the last part
// rather than on its own.
func TestMpuCrcTheCompletionCoversAHeldShortPart(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	first := MpuPayload(MpuStorablePart)
	short := MpuPayload(4096)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, first).Code)
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 2, short).Code)

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1, 2)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, MpuCrcwant(append(append([]byte(nil), first...), short...)),
		w.Header().Get("x-amz-checksum-crc32c"))
}

// Under the exit provider the proxy seals nothing and keeps no part table, so it
// has no checksum of its own on either verb.
func TestMpuCrcTheExitProviderStatesNoChecksum(t *testing.T) {
	env := MpuNewExitEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.backend.On("UploadPart", mock.Anything, mock.Anything).
		Return(&s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil)

	part := env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(1024))
	require.Equal(t, http.StatusOK, part.Code, part.Body.String())
	assert.Empty(t, part.Header().Get("x-amz-checksum-crc32c"))

	env.backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).
		Return(&s3.CompleteMultipartUploadOutput{ETag: aws.String(`"mpu-etag"`)}, nil)

	w := env.MpuComplete(t, MpuUploadID, 1)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Empty(t, w.Header().Get("x-amz-checksum-crc32c"))
}

// A refused part answers no checksum: there is nothing stored to describe.
func TestMpuCrcARefusedPartStatesNoChecksum(t *testing.T) {
	env := MpuNewEnv(t)
	env.MpuInitiate(t, MpuUploadID)
	env.MpuCaptureParts(t)

	// Two short parts in one session: the second can only be a last part and the
	// session already holds one.
	require.Equal(t, http.StatusOK, env.MpuUploadPart(t, MpuUploadID, 1, MpuPayload(1024)).Code)

	second := env.MpuUploadPart(t, MpuUploadID, 2, MpuPayload(2048))

	require.Equal(t, http.StatusBadRequest, second.Code, second.Body.String())
	assert.Empty(t, second.Header().Get("x-amz-checksum-crc32c"))
}
