package bucket

import (
	"bytes"
	"crypto/md5" // #nosec G501 - Content-MD5 is the digest S3 defines for this request
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
)

// The eight bucket configuration PUTs read their body through the request
// parser, so they inherit both the aws-chunked decoding and the checksum
// verification (ADR 0012 D2). Nothing else in this package feeds them framed
// bodies, which is the whole gap this file closes: a handler that parsed the
// framing instead of the payload would store chunk headers as configuration.

// BktChunkedHandler builds a bucket Handler for the framed-body cases. It is
// BktnewHandlerWith with a name that says what these tests feed it; aws-chunked
// decoding is not configurable.
func BktChunkedHandler(backend interfaces.S3BackendInterface) *Handler {
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	return NewHandler(backend, nil, logger, &config.Config{})
}

// BktChunkedBody frames payload the way aws-sdk-go-v2 does over TLS: unsigned
// chunks closed by a CRC32 trailer. trailer overrides the value that is sent, so
// a test can send a wrong one.
func BktChunkedBody(payload []byte, trailer string) []byte {
	if trailer == "" {
		sum := crc32.ChecksumIEEE(payload)
		trailer = base64.StdEncoding.EncodeToString(
			[]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%x\r\n", len(payload))
	buf.Write(payload)
	buf.WriteString("\r\n0\r\n")
	fmt.Fprintf(&buf, "x-amz-checksum-crc32:%s\r\n\r\n", trailer)
	return buf.Bytes()
}

func BktChunkedRequest(method, url string, payload []byte, trailer string) *http.Request {
	framed := BktChunkedBody(payload, trailer)
	req := httptest.NewRequest(method, url, bytes.NewReader(framed))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
	req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	req.ContentLength = int64(len(framed))
	return mux.SetURLVars(req, map[string]string{"bucket": bktBucket})
}

// bktChunkedTarget is one sub-resource PUT: the document a client sends, the
// backend call it becomes when it is applied, and the status a correct request
// answers. Four of the eight refuse a non-empty body outright (501), which is
// still the right answer to prove: the handler decoded the framing far enough
// to see a document rather than chunk headers.
type bktChunkedTarget struct {
	name        string
	url         string
	body        string
	backendCall string
	wantStatus  int
	run         func(h *Handler) http.HandlerFunc
}

func bktChunkedTargets() []bktChunkedTarget {
	return []bktChunkedTarget{
		{
			name: "acl", url: "/" + bktBucket + "?acl",
			body:        `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList></AccessControlList></AccessControlPolicy>`,
			backendCall: "PutBucketAcl", wantStatus: http.StatusOK,
			run: func(h *Handler) http.HandlerFunc { return h.GetACLHandler().Handle },
		},
		{
			name: "cors", url: "/" + bktBucket + "?cors",
			body:        `<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`,
			backendCall: "PutBucketCors", wantStatus: http.StatusOK,
			run: func(h *Handler) http.HandlerFunc { return h.GetCORSHandler().Handle },
		},
		{
			name: "policy", url: "/" + bktBucket + "?policy",
			body:        `{"Version":"2012-10-17","Statement":[]}`,
			backendCall: "PutBucketPolicy", wantStatus: http.StatusNoContent,
			run: func(h *Handler) http.HandlerFunc { return h.GetPolicyHandler().Handle },
		},
		{
			name: "logging", url: "/" + bktBucket + "?logging",
			body:        `<BucketLoggingStatus></BucketLoggingStatus>`,
			backendCall: "PutBucketLogging", wantStatus: http.StatusOK,
			run: func(h *Handler) http.HandlerFunc { return h.GetLoggingHandler().Handle },
		},
		{
			name: "lifecycle", url: "/" + bktBucket + "?lifecycle",
			body:       `<LifecycleConfiguration></LifecycleConfiguration>`,
			wantStatus: http.StatusNotImplemented,
			run:        func(h *Handler) http.HandlerFunc { return h.GetLifecycleHandler().Handle },
		},
		{
			name: "notification", url: "/" + bktBucket + "?notification",
			body:       `<NotificationConfiguration></NotificationConfiguration>`,
			wantStatus: http.StatusNotImplemented,
			run:        func(h *Handler) http.HandlerFunc { return h.GetNotificationHandler().Handle },
		},
		{
			name: "versioning", url: "/" + bktBucket + "?versioning",
			body:       `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
			wantStatus: http.StatusNotImplemented,
			run:        func(h *Handler) http.HandlerFunc { return h.GetVersioningHandler().Handle },
		},
		{
			name: "tagging", url: "/" + bktBucket + "?tagging",
			body:       `<Tagging><TagSet></TagSet></Tagging>`,
			wantStatus: http.StatusNotImplemented,
			run:        func(h *Handler) http.HandlerFunc { return h.GetTaggingHandler().Handle },
		},
	}
}

// A correct trailer applies the configuration, and the document the backend gets
// is the payload rather than the framing around it.
func TestBktChunkedBodyWithACorrectTrailerIsApplied(t *testing.T) {
	for _, target := range bktChunkedTargets() {
		t.Run(target.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			if target.backendCall != "" {
				backend.On(target.backendCall, mock.Anything, mock.Anything).
					Return(bktChunkedOutput(target.backendCall), nil)
			}
			h := BktChunkedHandler(backend)

			w := httptest.NewRecorder()
			target.run(h)(w, BktChunkedRequest(http.MethodPut, target.url, []byte(target.body), ""))

			require.Equal(t, target.wantStatus, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), "chunk", "no framing may reach the answer")
			if target.backendCall != "" {
				backend.AssertExpectations(t)
			}
		})
	}
}

// A wrong trailer answers 400 BadDigest and the configuration is left alone.
func TestBktChunkedBodyWithAWrongTrailerIsRefused(t *testing.T) {
	for _, target := range bktChunkedTargets() {
		t.Run(target.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			h := BktChunkedHandler(backend)

			w := httptest.NewRecorder()
			target.run(h)(w, BktChunkedRequest(
				http.MethodPut, target.url, []byte(target.body), "AAAAAA=="))

			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "<Code>BadDigest</Code>")
			if target.backendCall != "" {
				backend.AssertNotCalled(t, target.backendCall, mock.Anything, mock.Anything)
			}
		})
	}
}

// A trailer value that is not a digest at all is InvalidDigest: the request is
// malformed rather than the document wrong.
func TestBktChunkedBodyWithAMalformedTrailerIsRefused(t *testing.T) {
	backend := &MockS3Backend{}
	h := BktChunkedHandler(backend)

	w := httptest.NewRecorder()
	h.GetCORSHandler().Handle(w, BktChunkedRequest(http.MethodPut, "/"+bktBucket+"?cors",
		[]byte(`<CORSConfiguration></CORSConfiguration>`), "not-base64!!"))

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "<Code>InvalidDigest</Code>")
	backend.AssertNotCalled(t, "PutBucketCors", mock.Anything, mock.Anything)
}

func bktChunkedOutput(call string) interface{} {
	switch call {
	case "PutBucketAcl":
		return &s3.PutBucketAclOutput{}
	case "PutBucketCors":
		return &s3.PutBucketCorsOutput{}
	case "PutBucketPolicy":
		return &s3.PutBucketPolicyOutput{}
	case "PutBucketLogging":
		return &s3.PutBucketLoggingOutput{}
	}
	return nil
}

// A request that declares a digest and sends no body must still be verified.
// handleCreateBucket used to read the body only when a length was declared, and
// the verifier only runs where the body is read, so such a request reached the
// backend unchecked.
func TestBktCreateBucketVerifiesAnEmptyBodyDigest(t *testing.T) {
	wrong := md5.Sum([]byte("a configuration the client never sent")) // #nosec G401

	t.Run("wrong_digest_is_refused", func(t *testing.T) {
		backend := &MockS3Backend{}
		h := BktChunkedHandler(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket, nil)
		req.ContentLength = 0
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(wrong[:]))

		w := httptest.NewRecorder()
		h.Handle(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "<Code>BadDigest</Code>")
		backend.AssertNotCalled(t, "CreateBucket", mock.Anything, mock.Anything)
	})

	t.Run("correct_digest_creates_the_bucket", func(t *testing.T) {
		empty := md5.Sum(nil) // #nosec G401
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.Anything).
			Return(&s3.CreateBucketOutput{}, nil)
		h := BktChunkedHandler(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket, nil)
		req.ContentLength = 0
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(empty[:]))

		w := httptest.NewRecorder()
		h.Handle(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		backend.AssertExpectations(t)
	})
}
