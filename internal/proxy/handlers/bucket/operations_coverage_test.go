package bucket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// BktcaptureV2 registers ListObjectsV2 on the backend and returns a pointer that
// holds the input the handler built, so a test can assert on what the proxy
// asked the backend for rather than on how it asked.
func BktcaptureV2(backend *MockS3Backend, out *s3.ListObjectsV2Output) **s3.ListObjectsV2Input {
	captured := new(*s3.ListObjectsV2Input)
	backend.On("ListObjectsV2", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*captured = args.Get(1).(*s3.ListObjectsV2Input)
	}).Return(out, nil)
	return captured
}

// BktcaptureV1 is the ListObjects (V1) equivalent of BktcaptureV2.
func BktcaptureV1(backend *MockS3Backend, out *s3.ListObjectsOutput) **s3.ListObjectsInput {
	captured := new(*s3.ListObjectsInput)
	backend.On("ListObjects", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*captured = args.Get(1).(*s3.ListObjectsInput)
	}).Return(out, nil)
	return captured
}

// BktcaptureHead registers HeadBucket and returns a pointer to the input the
// handler built.
func BktcaptureHead(backend *MockS3Backend, out *s3.HeadBucketOutput) **s3.HeadBucketInput {
	captured := new(*s3.HeadBucketInput)
	backend.On("HeadBucket", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*captured = args.Get(1).(*s3.HeadBucketInput)
	}).Return(out, nil)
	return captured
}

// bktCaller is the access key the auth middleware puts on every S3 request. A
// listing's <Owner> is the caller and never the backend account (ADR 0008), so
// a test that expects an owner has to build the request with an identity.
const bktCaller = "AKIAPROXYCLIENT"

// bktAESKey is a valid 256-bit key. The listing asks the manager exactly one
// question - does the active provider encrypt - but building one takes a real
// key.
const bktAESKey = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// BktauthGet runs one authenticated GET against the bucket handler, the shape
// the auth middleware hands every S3 route.
func BktauthGet(h *Handler, url string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.Handle(w, middleware.WithClientIdentity(Bktrequest(http.MethodGet, url, nil), bktCaller))
	return w
}

// BktnewHandlerWithConfig builds a bucket Handler over a config the test cares
// about - the region HeadBucket falls back to, above all.
func BktnewHandlerWithConfig(backend interfaces.S3BackendInterface, cfg *config.Config) *Handler {
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	return NewHandler(backend, nil, logger, cfg)
}

// BktnewHandlerWithProvider builds a bucket Handler behind a real provider:
// "aes" encrypts, "exit" writes plaintext. Only the reported <Size> depends on
// which one is active.
func BktnewHandlerWithProvider(t *testing.T, backend interfaces.S3BackendInterface, providerType string) *Handler {
	t.Helper()

	provider := config.EncryptionProvider{Alias: "listing-provider", Type: providerType}
	if providerType == "aes" {
		provider.Config = map[string]interface{}{"aes_key": bktAESKey}
	}
	prefix := "s3ep-"
	cfg := &config.Config{Encryption: config.EncryptionConfig{
		EncryptionMethodAlias: "listing-provider",
		MetadataKeyPrefix:     &prefix,
		Providers:             []config.EncryptionProvider{provider},
	}}

	mgr, err := orchestration.NewManager(cfg)
	require.NoError(t, err)

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	return NewHandler(backend, mgr, logger, cfg)
}

// BktchildElements returns, in document order, the direct child elements of
// every element reached by path, read off the raw body.
//
// Element ORDER is the one property an SDK cannot check on our behalf: it
// unmarshals by local name and accepts any permutation, while the order S3
// emits is exactly what a schema-validating client verifies. Children of every
// element matching the path are concatenated, so a path ending in "Contents"
// over several entries returns them one entry after the other.
func BktchildElements(t *testing.T, body []byte, path ...string) []string {
	t.Helper()
	require.NotEmpty(t, path, "a path is required")

	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack, out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			require.ErrorIs(t, err, io.EOF, "body is not well-formed XML: %s", body)
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if bktPathIs(stack, path) {
				out = append(out, el.Name.Local)
			}
			stack = append(stack, el.Name.Local)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	require.NotEmpty(t, out, "no <%s> with children in: %s", path[len(path)-1], body)
	return out
}

func bktPathIs(stack, path []string) bool {
	if len(stack) != len(path) {
		return false
	}
	for i := range path {
		if stack[i] != path[i] {
			return false
		}
	}
	return true
}

// bktSDKOnlyElements are elements the aws-sdk-go-v2 output struct carries and a
// real S3 listing never does. The two checksum elements are absent on purpose
// and not merely for tidiness: a backend checksum describes the stored
// ciphertext, and the proxy holds no plaintext checksum it could report
// instead, so the honest answer is to emit none.
var bktSDKOnlyElements = []string{"<ResultMetadata", "<RequestCharged", "<ChecksumAlgorithm", "<ChecksumType"}

// BktassertNoSDKElements fails if the document leaks an SDK-internal element.
func BktassertNoSDKElements(t *testing.T, body string) {
	t.Helper()
	for _, el := range bktSDKOnlyElements {
		assert.NotContains(t, body, el, "element the SDK output struct carries and S3 does not")
	}
}

// BktassertIsListBucketResult asserts the frame every listing document shares:
// the XML prolog, the root element, and the S3 namespace on it.
func BktassertIsListBucketResult(t *testing.T, body string) {
	t.Helper()
	assert.True(t, strings.HasPrefix(body, xml.Header), "no XML prolog: %s", body)
	assert.Contains(t, body, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
		"root element and namespace")
	assert.True(t, strings.HasSuffix(body, "</ListBucketResult>"), "document does not close its root: %s", body)
}

// TestBktListObjectsV2IsARealListBucketResult asserts the exact bytes a client
// receives.
//
// The document used to be the aws-sdk-go-v2 output struct marshalled by field
// name: root element <ListObjectsV2Output>, no namespace, no XML prolog, and
// SDK-internal elements (<ResultMetadata>, <RequestCharged>, <ChecksumType>) on
// the wire. aws-sdk-go-v2 and minio-go survived it because they match by local
// name and ignore the root; a schema-validating client did not. That is the
// defect ADR 0010 closes, and this test is its inverse.
func TestBktListObjectsV2IsARealListBucketResult(t *testing.T) {
	modified := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:   aws.String(bktBucket),
		Prefix: aws.String("docs/"),
		// The backend counts Contents plus CommonPrefixes here and the proxy
		// forwards the number it computed; the fixture mirrors that rule.
		KeyCount:    aws.Int32(2),
		MaxKeys:     aws.Int32(1000),
		IsTruncated: aws.Bool(false),
		Contents: []s3types.Object{{
			Key:               aws.String("docs/report.pdf"),
			Size:              aws.Int64(1_048_604),
			LastModified:      &modified,
			ETag:              aws.String(`"ciphertext-etag"`),
			StorageClass:      s3types.ObjectStorageClassStandard,
			ChecksumAlgorithm: []s3types.ChecksumAlgorithm{s3types.ChecksumAlgorithmCrc32},
			ChecksumType:      s3types.ChecksumTypeFullObject,
		}},
		CommonPrefixes: []s3types.CommonPrefix{{Prefix: aws.String("docs/archive/")}},
	})
	h := BktnewHandlerWith(backend)

	w := BktauthGet(h, "/"+bktBucket+"?list-type=2&prefix=docs/&delimiter=/")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	body := w.Body.String()

	BktassertIsListBucketResult(t, body)
	assert.NotContains(t, body, "<ListObjectsV2Output", "the SDK output struct must not be the wire document")
	BktassertNoSDKElements(t, body)
	assert.NotContains(t, body, "<EncodingType", "the client did not ask for encoding-type")

	// The content itself, including the timestamp format: S3 writes RFC 3339
	// with exactly three fractional digits, which Go's time.Time does not.
	assert.Contains(t, body, "<Name>"+bktBucket+"</Name>")
	assert.Contains(t, body, "<Prefix>docs/</Prefix>")
	assert.Contains(t, body, "<KeyCount>2</KeyCount>")
	assert.Contains(t, body, "<MaxKeys>1000</MaxKeys>")
	assert.Contains(t, body, "<IsTruncated>false</IsTruncated>")
	assert.Contains(t, body, "<Key>docs/report.pdf</Key>")
	assert.Contains(t, body, "<LastModified>2026-03-04T05:06:07.000Z</LastModified>")
	assert.Contains(t, body, "<CommonPrefixes><Prefix>docs/archive/</Prefix></CommonPrefixes>")
	// The ETag is the backend's, and it is the MD5 of the stored ciphertext. It
	// is forwarded because a client uses it as an opaque change token; nothing
	// here claims it describes the plaintext.
	assert.Contains(t, body, `<ETag>&#34;ciphertext-etag&#34;</ETag>`)
}

// TestBktListObjectsV1IsARealListBucketResult is the same frame for the V1
// listing, which the aws CLI still uses for `s3api list-objects`. Same root
// element, same namespace, and no <KeyCount> - that element belongs to V2.
func TestBktListObjectsV1IsARealListBucketResult(t *testing.T) {
	modified := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	backend := &MockS3Backend{}
	BktcaptureV1(backend, &s3.ListObjectsOutput{
		Name:        aws.String(bktBucket),
		Prefix:      aws.String("docs/"),
		Marker:      aws.String(""),
		MaxKeys:     aws.Int32(1000),
		IsTruncated: aws.Bool(false),
		Contents: []s3types.Object{{
			Key:               aws.String("docs/report.pdf"),
			Size:              aws.Int64(1_048_604),
			LastModified:      &modified,
			ETag:              aws.String(`"ciphertext-etag"`),
			StorageClass:      s3types.ObjectStorageClassStandard,
			ChecksumAlgorithm: []s3types.ChecksumAlgorithm{s3types.ChecksumAlgorithmCrc32},
			ChecksumType:      s3types.ChecksumTypeFullObject,
		}},
		CommonPrefixes: []s3types.CommonPrefix{{Prefix: aws.String("docs/archive/")}},
	})
	h := BktnewHandlerWith(backend)

	w := BktauthGet(h, "/"+bktBucket+"?prefix=docs/&delimiter=/")

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	BktassertIsListBucketResult(t, body)
	assert.NotContains(t, body, "<ListObjectsOutput", "the SDK output struct must not be the wire document")
	BktassertNoSDKElements(t, body)
	assert.NotContains(t, body, "<EncodingType", "the client did not ask for encoding-type")
	assert.NotContains(t, body, "<KeyCount", "KeyCount is a V2 element")
	assert.Contains(t, body, "<Marker></Marker>", "V1 always carries the marker, empty on the first page")
	assert.Contains(t, body, "<Key>docs/report.pdf</Key>")
	assert.Contains(t, body, "<LastModified>2026-03-04T05:06:07.000Z</LastModified>")
}

// TestBktListObjectsElementOrder asserts the ORDER of the elements, not only
// that they are present. It is the assertion the SDK cannot make and the one a
// schema-validating client depends on; the order below was captured from a
// running backend, not read out of the API reference.
func TestBktListObjectsElementOrder(t *testing.T) {
	modified := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	t.Run("v2", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:                  aws.String(bktBucket),
			Prefix:                aws.String("docs/"),
			StartAfter:            aws.String("docs/a.pdf"),
			ContinuationToken:     aws.String("token-in"),
			NextContinuationToken: aws.String("token-out"),
			KeyCount:              aws.Int32(2),
			MaxKeys:               aws.Int32(1000),
			Delimiter:             aws.String("/"),
			IsTruncated:           aws.Bool(true),
			Contents: []s3types.Object{{
				Key:          aws.String("docs/report.pdf"),
				Size:         aws.Int64(168),
				LastModified: &modified,
				ETag:         aws.String(`"etag"`),
				StorageClass: s3types.ObjectStorageClassStandard,
			}},
			CommonPrefixes: []s3types.CommonPrefix{{Prefix: aws.String("docs/archive/")}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&fetch-owner=true&encoding-type=url")

		require.Equal(t, http.StatusOK, w.Code)
		order := BktchildElements(t, w.Body.Bytes(), "ListBucketResult")
		assert.Equal(t, []string{
			"Name", "Prefix", "StartAfter", "ContinuationToken", "NextContinuationToken",
			"KeyCount", "MaxKeys", "Delimiter", "IsTruncated", "Contents", "CommonPrefixes", "EncodingType",
		}, order)
		// Spelled out separately because these two are the ones a rewrite gets
		// wrong: NextContinuationToken sits before KeyCount, and EncodingType is
		// last, after CommonPrefixes.
		assert.Equal(t, "EncodingType", order[len(order)-1])
		assert.Less(t, bktIndexOf(order, "NextContinuationToken"), bktIndexOf(order, "KeyCount"))
	})

	t.Run("v2_contents", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name: aws.String(bktBucket),
			Contents: []s3types.Object{{
				Key:          aws.String("a"),
				Size:         aws.Int64(168),
				LastModified: &modified,
				ETag:         aws.String(`"etag"`),
				StorageClass: s3types.ObjectStorageClassStandard,
			}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&fetch-owner=true")

		require.Equal(t, http.StatusOK, w.Code)
		order := BktchildElements(t, w.Body.Bytes(), "ListBucketResult", "Contents")
		assert.Equal(t, []string{"Key", "LastModified", "ETag", "Size", "Owner", "StorageClass"}, order)
		// Owner sits between Size and StorageClass, which is where the backend
		// puts it and where a client that reads positionally looks for it.
		assert.Equal(t, "Size", order[bktIndexOf(order, "Owner")-1])
		assert.Equal(t, "StorageClass", order[bktIndexOf(order, "Owner")+1])
	})

	t.Run("v1", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV1(backend, &s3.ListObjectsOutput{
			Name:        aws.String(bktBucket),
			Prefix:      aws.String("docs/"),
			Marker:      aws.String("docs/a.pdf"),
			NextMarker:  aws.String("docs/z.pdf"),
			MaxKeys:     aws.Int32(1000),
			Delimiter:   aws.String("/"),
			IsTruncated: aws.Bool(true),
			Contents: []s3types.Object{{
				Key:          aws.String("docs/report.pdf"),
				Size:         aws.Int64(168),
				LastModified: &modified,
				ETag:         aws.String(`"etag"`),
				StorageClass: s3types.ObjectStorageClassStandard,
			}},
			CommonPrefixes: []s3types.CommonPrefix{{Prefix: aws.String("docs/archive/")}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?encoding-type=url")

		require.Equal(t, http.StatusOK, w.Code)
		order := BktchildElements(t, w.Body.Bytes(), "ListBucketResult")
		assert.Equal(t, []string{
			"Name", "Prefix", "Marker", "NextMarker", "MaxKeys", "Delimiter",
			"IsTruncated", "Contents", "CommonPrefixes", "EncodingType",
		}, order)
		assert.Equal(t, "EncodingType", order[len(order)-1])

		contents := BktchildElements(t, w.Body.Bytes(), "ListBucketResult", "Contents")
		assert.Equal(t, []string{"Key", "LastModified", "ETag", "Size", "Owner", "StorageClass"}, contents)
	})
}

func bktIndexOf(elements []string, name string) int {
	for i, e := range elements {
		if e == name {
			return i
		}
	}
	return -1
}

// TestBktListObjectsOwnerIsTheCaller pins who <Owner> names. S3 returns an
// opaque canonical id there; the proxy has no such id for its own clients and
// answers with the access key that authenticated the request, never the backend
// account it uses downstream (ADR 0008).
func TestBktListObjectsOwnerIsTheCaller(t *testing.T) {
	type ownerDoc struct {
		Contents []struct {
			Owner *struct {
				ID          string `xml:"ID"`
				DisplayName string `xml:"DisplayName"`
			} `xml:"Owner"`
		} `xml:"Contents"`
	}
	parse := func(t *testing.T, body []byte) ownerDoc {
		t.Helper()
		var doc ownerDoc
		require.NoError(t, xml.Unmarshal(body, &doc))
		require.Len(t, doc.Contents, 1)
		return doc
	}

	t.Run("v2_with_fetch_owner", func(t *testing.T) {
		backend := &MockS3Backend{}
		captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&fetch-owner=true")

		require.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, *captured)
		assert.True(t, aws.ToBool((*captured).FetchOwner), "the backend is asked too, so it can page consistently")
		owner := parse(t, w.Body.Bytes()).Contents[0].Owner
		require.NotNil(t, owner, "the client asked for the owner: %s", w.Body.String())
		assert.Equal(t, bktCaller, owner.ID)
		assert.Equal(t, bktCaller, owner.DisplayName)
	})

	t.Run("v2_without_fetch_owner", func(t *testing.T) {
		backend := &MockS3Backend{}
		captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, *captured)
		assert.Nil(t, (*captured).FetchOwner)
		assert.NotContains(t, w.Body.String(), "<Owner>", "no owner unless the client asks for one")
		assert.Nil(t, parse(t, w.Body.Bytes()).Contents[0].Owner)
	})

	t.Run("v1_carries_the_owner_unasked", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV1(backend, &s3.ListObjectsOutput{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket)

		require.Equal(t, http.StatusOK, w.Code)
		owner := parse(t, w.Body.Bytes()).Contents[0].Owner
		require.NotNil(t, owner, "V1 has no fetch-owner: the owner comes unasked")
		assert.Equal(t, bktCaller, owner.ID)
	})

	t.Run("no_identity_means_no_owner", func(t *testing.T) {
		// Not reachable through the router - the auth middleware sets an
		// identity on every S3 route - but the handler must not invent one.
		backend := &MockS3Backend{}
		BktcaptureV1(backend, &s3.ListObjectsOutput{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket, nil)

		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), "<Owner>")
	})
}

// TestBktListObjectsV2ParameterHandling walks every listing parameter a client
// can send and asserts which of them reach the backend. start-after and
// fetch-owner used to be dropped, which meant a client paging with StartAfter
// was served the same first page forever.
func TestBktListObjectsV2ParameterHandling(t *testing.T) {
	cases := []struct {
		name  string
		query string
		check func(t *testing.T, in *s3.ListObjectsV2Input)
	}{
		{"prefix_is_forwarded", "prefix=a/b", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, "a/b", aws.ToString(in.Prefix))
		}},
		{"empty_prefix_is_left_unset", "prefix=", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.Prefix)
		}},
		{"delimiter_is_forwarded", "delimiter=/", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, "/", aws.ToString(in.Delimiter))
		}},
		{"empty_delimiter_is_left_unset", "delimiter=", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.Delimiter)
		}},
		{"continuation_token_is_forwarded", "continuation-token=abc%3D", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, "abc=", aws.ToString(in.ContinuationToken))
		}},
		{"start_after_is_forwarded", "start-after=key-500", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, "key-500", aws.ToString(in.StartAfter), "paging with start-after must move forward")
		}},
		{"fetch_owner_is_forwarded", "fetch-owner=true", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.True(t, aws.ToBool(in.FetchOwner))
		}},
		{"fetch_owner_false_is_left_unset", "fetch-owner=false", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.FetchOwner)
		}},
		// The proxy asks the backend for URL encoding whatever the client
		// wanted: that is what makes the backend's XML well formed no matter
		// what bytes a key contains. It decodes before it builds its own
		// document, and re-encodes only when the client asked.
		{"backend_is_always_asked_for_url_encoding", "encoding-type=url", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, s3types.EncodingTypeUrl, in.EncodingType)
		}},
		{"backend_is_asked_for_url_encoding_unasked", "prefix=a/", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Equal(t, s3types.EncodingTypeUrl, in.EncodingType)
		}},
		{"marker_is_a_v1_parameter_and_is_ignored", "marker=key-500", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.ContinuationToken)
			assert.Nil(t, in.StartAfter)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?list-type=2&"+tc.query)

			require.Equal(t, http.StatusOK, w.Code)
			require.NotNil(t, *captured)
			assert.Equal(t, bktBucket, aws.ToString((*captured).Bucket))
			tc.check(t, *captured)
		})
	}

	t.Run("encoding_type_is_echoed_only_when_asked", func(t *testing.T) {
		for _, tc := range []struct {
			query string
			want  bool
		}{
			{"", false},
			{"&encoding-type=url", true},
		} {
			backend := &MockS3Backend{}
			BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?list-type=2"+tc.query)

			require.Equal(t, http.StatusOK, w.Code)
			if tc.want {
				assert.Contains(t, w.Body.String(), "<EncodingType>url</EncodingType>")
			} else {
				assert.NotContains(t, w.Body.String(), "<EncodingType")
			}
		}
	})
}

// TestBktListObjectsMaxKeys is the whole max-keys table, for both listing
// versions. Out-of-range and unparseable values used to be dropped silently, so
// a client asking for 0 keys or sending a negative number was served a full
// page instead of an answer or a refusal.
func TestBktListObjectsMaxKeys(t *testing.T) {
	accepted := []struct {
		value   string
		wantSet bool
		want    int32
		note    string
	}{
		{"", false, 0, "absent: the backend default applies"},
		{"0", true, 0, "a client asking for no keys is asking a real question"},
		{"1", true, 1, "lower bound"},
		{"999", true, 999, "just inside the upper bound"},
		{"1000", true, 1000, "upper bound"},
		{"1001", true, 1000, "one past the bound: clamped"},
		// The clamp is the proxy's own behaviour and a deliberate deviation
		// from the development backend, which echoes 5000 and returns
		// everything.
		{"5000", true, 1000, "clamped to the page limit"},
	}

	for _, tc := range accepted {
		t.Run("v2/max-keys="+tc.value, func(t *testing.T) {
			backend := &MockS3Backend{}
			captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?list-type=2&max-keys="+tc.value)

			require.Equal(t, http.StatusOK, w.Code, tc.note)
			require.NotNil(t, *captured)
			if tc.wantSet {
				require.NotNil(t, (*captured).MaxKeys, tc.note)
				assert.Equal(t, tc.want, *(*captured).MaxKeys, tc.note)
			} else {
				assert.Nil(t, (*captured).MaxKeys, tc.note)
			}
		})

		t.Run("v1/max-keys="+tc.value, func(t *testing.T) {
			backend := &MockS3Backend{}
			captured := BktcaptureV1(backend, &s3.ListObjectsOutput{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?max-keys="+tc.value)

			require.Equal(t, http.StatusOK, w.Code, tc.note)
			require.NotNil(t, *captured)
			if tc.wantSet {
				require.NotNil(t, (*captured).MaxKeys, tc.note)
				assert.Equal(t, tc.want, *(*captured).MaxKeys, tc.note)
			} else {
				assert.Nil(t, (*captured).MaxKeys, tc.note)
			}
		})
	}

	refused := []struct {
		value string
		note  string
	}{
		{"-1", "negative"},
		{"abc", "not an integer"},
		{"9223372036854775808", "int64 overflow, refused rather than crashed"},
	}

	for _, tc := range refused {
		t.Run("v2/refused/max-keys="+tc.value, func(t *testing.T) {
			backend := &MockS3Backend{}
			BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?list-type=2&max-keys="+tc.value)

			require.Equal(t, http.StatusBadRequest, w.Code, tc.note)
			doc := BktparseError(t, w.Body.Bytes())
			assert.Equal(t, "InvalidArgument", doc.Code, tc.note)
			assert.Equal(t, "max-keys must be a non-negative integer", doc.Message)
			backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
		})

		t.Run("v1/refused/max-keys="+tc.value, func(t *testing.T) {
			backend := &MockS3Backend{}
			BktcaptureV1(backend, &s3.ListObjectsOutput{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?max-keys="+tc.value)

			require.Equal(t, http.StatusBadRequest, w.Code, tc.note)
			assert.Equal(t, "InvalidArgument", BktparseError(t, w.Body.Bytes()).Code, tc.note)
			backend.AssertNotCalled(t, "ListObjects", mock.Anything, mock.Anything)
		})
	}

	// max-keys=0 against a bucket that holds objects: the backend answers with
	// an empty page rather than a full one, and the document says so.
	t.Run("zero_on_a_non_empty_bucket_is_an_empty_page", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:        aws.String(bktBucket),
			KeyCount:    aws.Int32(0),
			MaxKeys:     aws.Int32(0),
			IsTruncated: aws.Bool(false),
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&max-keys=0")

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "<KeyCount>0</KeyCount>")
		assert.Contains(t, body, "<MaxKeys>0</MaxKeys>")
		assert.Contains(t, body, "<IsTruncated>false</IsTruncated>")
		assert.NotContains(t, body, "<Contents>")
	})
}

// TestBktListObjectsV1ParameterHandling is the parameter walk for the V1
// listing, which used to drop even max-keys.
func TestBktListObjectsV1ParameterHandling(t *testing.T) {
	cases := []struct {
		name  string
		query string
		check func(t *testing.T, in *s3.ListObjectsInput)
	}{
		{"prefix_is_forwarded", "prefix=a/", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Equal(t, "a/", aws.ToString(in.Prefix))
		}},
		{"delimiter_is_forwarded", "delimiter=/", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Equal(t, "/", aws.ToString(in.Delimiter))
		}},
		{"marker_is_forwarded", "marker=key-500", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Equal(t, "key-500", aws.ToString(in.Marker))
		}},
		{"max_keys_is_forwarded", "max-keys=1", func(t *testing.T, in *s3.ListObjectsInput) {
			require.NotNil(t, in.MaxKeys)
			assert.Equal(t, int32(1), *in.MaxKeys)
		}},
		{"backend_is_always_asked_for_url_encoding", "encoding-type=url", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Equal(t, s3types.EncodingTypeUrl, in.EncodingType)
		}},
		{"continuation_token_is_a_v2_parameter_and_is_ignored", "continuation-token=t", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Nil(t, in.Marker)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			captured := BktcaptureV1(backend, &s3.ListObjectsOutput{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, "/"+bktBucket+"?"+tc.query)

			require.Equal(t, http.StatusOK, w.Code)
			require.NotNil(t, *captured)
			assert.Equal(t, bktBucket, aws.ToString((*captured).Bucket))
			tc.check(t, *captured)
		})
	}

	t.Run("list-type_other_than_2_takes_the_v1_branch", func(t *testing.T) {
		for _, listType := range []string{"", "1", "3", "two"} {
			backend := &MockS3Backend{}
			BktcaptureV1(backend, &s3.ListObjectsOutput{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			url := "/" + bktBucket
			if listType != "" {
				url += "?list-type=" + listType
			}
			w := BktauthGet(h, url)

			require.Equal(t, http.StatusOK, w.Code, "list-type=%q", listType)
			backend.AssertCalled(t, "ListObjects", mock.Anything, mock.Anything)
			backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
			// Both versions answer under the same root element.
			BktassertIsListBucketResult(t, w.Body.String())
		}
	})
}

// TestBktListObjectsEmptyBucketIsAWellFormedDocument covers the boundary a
// client hits most often after CreateBucket.
func TestBktListObjectsEmptyBucketIsAWellFormedDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"v2", "/" + bktBucket + "?list-type=2"},
		{"v1", "/" + bktBucket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			if tc.name == "v2" {
				BktcaptureV2(backend, &s3.ListObjectsV2Output{
					Name: aws.String(bktBucket), KeyCount: aws.Int32(0), IsTruncated: aws.Bool(false),
				})
			} else {
				BktcaptureV1(backend, &s3.ListObjectsOutput{
					Name: aws.String(bktBucket), IsTruncated: aws.Bool(false),
				})
			}
			h := BktnewHandlerWith(backend)

			w := BktauthGet(h, tc.url)

			require.Equal(t, http.StatusOK, w.Code)
			BktassertIsListBucketResult(t, w.Body.String())
			assert.NotContains(t, w.Body.String(), "<Contents>")
			var probe struct {
				XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
				Name    string   `xml:"Name"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &probe),
				"the document must parse as a namespaced ListBucketResult")
			assert.Equal(t, bktBucket, probe.Name)
		})
	}
}

// TestBktListObjectsAwkwardKeysStillParse is the property the old
// string-concatenated document lost and that must not come back: a key carrying
// XML metacharacters or a non-ASCII character still parses with encoding/xml
// and arrives as the key that is stored.
//
// The proxy always asks the backend for URL-encoded keys, so the fixture is
// what the backend returns for such a key.
func TestBktListObjectsAwkwardKeysStillParse(t *testing.T) {
	const key = `reports/a&b<c"d ümlaut→.pdf`
	encoded := url.QueryEscape(key)
	require.NotEqual(t, key, encoded, "fixture: the backend would encode this key")

	type keyDoc struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
		EncodingType string `xml:"EncodingType"`
	}

	t.Run("without_encoding_type_the_key_is_xml_escaped", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String(encoded)}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "&amp;", "the metacharacters are XML-escaped, not concatenated raw")
		assert.NotContains(t, body, `a&b`, "a raw ampersand would not parse")

		var doc keyDoc
		require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "the document must parse: %s", body)
		require.Len(t, doc.Contents, 1)
		assert.Equal(t, key, doc.Contents[0].Key, "the key the client receives is the key that is stored")
		assert.Empty(t, doc.EncodingType)
	})

	t.Run("with_encoding_type_the_key_comes_back_encoded", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String(encoded)}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&encoding-type=url")

		require.Equal(t, http.StatusOK, w.Code)
		var doc keyDoc
		require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &doc), "the document must parse: %s", w.Body.String())
		require.Len(t, doc.Contents, 1)
		assert.Equal(t, "url", doc.EncodingType)

		decoded, err := url.QueryUnescape(doc.Contents[0].Key)
		require.NoError(t, err)
		assert.Equal(t, key, decoded, "a client that asked for encoding decodes back to the stored key")
	})
}

// TestBktListObjectsSizeIsThePlaintextSize is the <Size> half of ADR 0010. A
// listing states the length a GET will deliver, computed from the stored length
// by arithmetic the proxy controls - no metadata, no per-key HeadObject on a
// path every S3 client hits constantly.
func TestBktListObjectsSizeIsThePlaintextSize(t *testing.T) {
	// The interesting plaintext lengths around the segment boundary, plus the
	// empty object: a client that treats size 0 as empty must still see 0.
	plaintexts := []int64{0, 1, dataencryption.SegmentSize - 1, dataencryption.SegmentSize,
		dataencryption.SegmentSize + 1, 12 << 20}

	contents := make([]s3types.Object, 0, len(plaintexts))
	stored := make([]int64, 0, len(plaintexts))
	for i, p := range plaintexts {
		c, err := dataencryption.CiphertextSize(p)
		require.NoError(t, err)
		stored = append(stored, c)
		contents = append(contents, s3types.Object{
			Key:  aws.String("object-" + strconv.Itoa(i)),
			Size: aws.Int64(c),
		})
	}

	sizes := func(t *testing.T, body []byte) []int64 {
		t.Helper()
		var doc struct {
			Contents []struct {
				Size int64 `xml:"Size"`
			} `xml:"Contents"`
		}
		require.NoError(t, xml.Unmarshal(body, &doc))
		out := make([]int64, 0, len(doc.Contents))
		for _, c := range doc.Contents {
			out = append(out, c.Size)
		}
		return out
	}

	t.Run("an_encrypting_provider_reports_the_plaintext_size", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket), Contents: contents})
		h := BktnewHandlerWithProvider(t, backend, "aes")

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, plaintexts, sizes(t, w.Body.Bytes()),
			"the listing must state the length a GET delivers, not the stored length")
	})

	// The listing rule under the exit provider is deliberate: <Size> is the
	// stored size, reported verbatim. Inverting the arithmetic would be exact
	// for objects encrypted before the switch but would under-report plain ones,
	// and a sync client that believes the remote is smaller may upload over it.
	// Over-reporting only costs a re-transfer.
	t.Run("the_exit_provider_reports_the_stored_size", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket), Contents: contents})
		h := BktnewHandlerWithProvider(t, backend, "exit")

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, stored, sizes(t, w.Body.Bytes()),
			"nothing was added to the object, so nothing is subtracted from its size")
	})

	t.Run("a_stored_size_no_chain_can_have_is_reported_verbatim", func(t *testing.T) {
		// 50 bytes is shorter than the smallest one-segment object and longer
		// than an empty one, so the arithmetic cannot invert it. That is a
		// foreign object - written past the proxy - and inventing a length for
		// it would be worse than reporting what the backend said.
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("foreign"), Size: aws.Int64(50)}},
		})
		h := BktnewHandlerWithProvider(t, backend, "aes")

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []int64{50}, sizes(t, w.Body.Bytes()))
	})

	t.Run("a_foreign_object_whose_size_inverts_is_under_reported", func(t *testing.T) {
		// The deliberate tradeoff of ADR 0010, asserted so it stays deliberate:
		// a foreign object whose stored length happens to be a valid chain
		// length is reported short. The alternative is one HeadObject per key
		// in every listing, which is the wrong price on this path. If this test
		// ever fails because the number got exact, someone added that HEAD.
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("foreign"), Size: aws.Int64(12345)}},
		})
		h := BktnewHandlerWithProvider(t, backend, "aes")

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []int64{12277}, sizes(t, w.Body.Bytes()), "short by the overhead of one segment and the trailer")
	})

	t.Run("without_a_manager_the_stored_size_is_reported", func(t *testing.T) {
		// The shape every other test in this file builds: no manager, so the
		// handler cannot know whether anything encrypts and reports what the
		// backend said.
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket), Contents: contents})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, stored, sizes(t, w.Body.Bytes()))
	})
}

// TestBktListObjectsLargePageIsForwardedByteForByte compares a full page of
// keys by sha256 of the concatenated <Key> values, so a reordering or a dropped
// entry fails without a hex dump in the output.
func TestBktListObjectsLargePageIsForwardedByteForByte(t *testing.T) {
	const keys = 1000
	contents := make([]s3types.Object, 0, keys)
	digest := sha256.New()
	for i := 0; i < keys; i++ {
		key := "prefix/" + strconv.Itoa(i) + ".bin"
		contents = append(contents, s3types.Object{Key: aws.String(key), Size: aws.Int64(int64(i))})
		digest.Write([]byte(key))
	}
	want := hex.EncodeToString(digest.Sum(nil))

	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:                  aws.String(bktBucket),
		KeyCount:              aws.Int32(keys),
		IsTruncated:           aws.Bool(true),
		NextContinuationToken: aws.String("next-page"),
		Contents:              contents,
	})
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2&max-keys=1000", nil)

	require.Equal(t, http.StatusOK, w.Code)

	var got struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Contents, keys)

	back := sha256.New()
	for _, c := range got.Contents {
		back.Write([]byte(c.Key))
	}
	assert.Equal(t, want, hex.EncodeToString(back.Sum(nil)), "the key set changed on the way to the client")
	assert.True(t, got.IsTruncated)
	assert.Equal(t, "next-page", got.NextContinuationToken, "pagination state is forwarded, so paging works")
}

// TestBktListObjectsBackendErrors covers the error arm of both listing branches.
// There is one error writer now; this used to go through a second implementation
// of the same document.
func TestBktListObjectsBackendErrors(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		call       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"v2_NoSuchBucket", "?list-type=2", "ListObjectsV2",
			BktapiError("NoSuchBucket", "The specified bucket does not exist"), http.StatusNotFound, "NoSuchBucket"},
		{"v2_AccessDenied", "?list-type=2", "ListObjectsV2",
			BktapiError("AccessDenied", "Access Denied"), http.StatusForbidden, "AccessDenied"},
		{"v1_NoSuchBucket", "", "ListObjects",
			BktapiError("NoSuchBucket", "The specified bucket does not exist"), http.StatusNotFound, "NoSuchBucket"},
		{"v1_network_error", "", "ListObjects",
			errIsNotAnAPIError, http.StatusInternalServerError, "InternalError"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &MockS3Backend{}
			backend.On(tc.call, mock.Anything, mock.Anything).Return(nil, tc.err)
			h := BktnewHandlerWith(backend)

			w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+tc.url, nil)

			assert.Equal(t, tc.wantStatus, w.Code)
			doc := BktparseError(t, w.Body.Bytes())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.Equal(t, bktBucket, doc.Resource)
			assert.NotContains(t, w.Body.String(), "10.9.9.9", "the backend endpoint must not leak")
		})
	}
}

// TestBktCreateBucketParsesTheLocationConstraint covers handleCreateBucket.
func TestBktCreateBucketParsesTheLocationConstraint(t *testing.T) {
	t.Run("constraint_is_forwarded", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return aws.ToString(in.Bucket) == bktBucket && in.CreateBucketConfiguration != nil &&
				in.CreateBucketConfiguration.LocationConstraint == s3types.BucketLocationConstraintEuCentral1
		})).Return(&s3.CreateBucketOutput{Location: aws.String("/" + bktBucket)}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodPut, "/"+bktBucket,
			[]byte(`<CreateBucketConfiguration><LocationConstraint>eu-central-1</LocationConstraint></CreateBucketConfiguration>`))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "/"+bktBucket, w.Header().Get("Location"))
		assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
		assert.Empty(t, w.Body.String())
		backend.AssertExpectations(t)
	})

	t.Run("no_body_means_the_default_region", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return in.CreateBucketConfiguration == nil
		})).Return(&s3.CreateBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodPut, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Location"), "no Location header when the backend reported none")
		backend.AssertExpectations(t)
	})

	t.Run("empty_constraint_element_is_ignored", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return in.CreateBucketConfiguration == nil
		})).Return(&s3.CreateBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodPut, "/"+bktBucket,
			[]byte(`<CreateBucketConfiguration><LocationConstraint></LocationConstraint></CreateBucketConfiguration>`))

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	// DEFECT, pinned deliberately: the decode error is discarded
	// (`if err := ...Decode(...); err == nil`), so a malformed
	// CreateBucketConfiguration creates the bucket in the backend's default
	// region and reports 200. AWS answers MalformedXML and creates nothing.
	t.Run("malformed_body_still_creates_the_bucket", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return in.CreateBucketConfiguration == nil
		})).Return(&s3.CreateBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodPut, "/"+bktBucket,
			[]byte(`<CreateBucketConfiguration><LocationConstraint>eu-central-1`))

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	// DEFECT, pinned deliberately: the body is only read when ContentLength is
	// positive. A client that sends the configuration with
	// Transfer-Encoding: chunked (ContentLength -1) has its region silently
	// discarded and the bucket lands wherever the backend defaults to.
	t.Run("chunked_body_loses_the_region", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return in.CreateBucketConfiguration == nil
		})).Return(&s3.CreateBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket,
			[]byte(`<CreateBucketConfiguration><LocationConstraint>eu-central-1</LocationConstraint></CreateBucketConfiguration>`))
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		w := httptest.NewRecorder()
		h.Handle(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("acl_and_grant_headers_are_forwarded", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
			return in.ACL == s3types.BucketCannedACLPrivate &&
				aws.ToString(in.GrantFullControl) == "id=full" &&
				aws.ToString(in.GrantRead) == "id=read" &&
				aws.ToString(in.GrantReadACP) == "id=readacp" &&
				aws.ToString(in.GrantWrite) == "id=write" &&
				aws.ToString(in.GrantWriteACP) == "id=writeacp"
		})).Return(&s3.CreateBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodPut, "/"+bktBucket, nil)
		req.Header.Set("x-amz-acl", "private")
		req.Header.Set("x-amz-grant-full-control", "id=full")
		req.Header.Set("x-amz-grant-read", "id=read")
		req.Header.Set("x-amz-grant-read-acp", "id=readacp")
		req.Header.Set("x-amz-grant-write", "id=write")
		req.Header.Set("x-amz-grant-write-acp", "id=writeacp")
		w := httptest.NewRecorder()
		h.Handle(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("backend_errors", func(t *testing.T) {
		for _, tc := range []struct {
			code       string
			wantStatus int
		}{
			{"BucketAlreadyExists", http.StatusConflict},
			{"BucketAlreadyOwnedByYou", http.StatusConflict},
			{"InvalidBucketName", http.StatusBadRequest},
			{"AccessDenied", http.StatusForbidden},
		} {
			t.Run(tc.code, func(t *testing.T) {
				backend := &MockS3Backend{}
				backend.On("CreateBucket", mock.Anything, mock.Anything).Return(nil, BktapiError(tc.code, ""))
				h := BktnewHandlerWith(backend)

				w := Bktserve(h.Handle, http.MethodPut, "/"+bktBucket, nil)

				assert.Equal(t, tc.wantStatus, w.Code)
				doc := BktparseError(t, w.Body.Bytes())
				assert.Equal(t, tc.code, doc.Code)
				assert.Equal(t, bktBucket, doc.Resource)
			})
		}
	})
}

// TestBktDeleteBucketAnswers204 covers handleDeleteBucket including the header
// it forwards and the conflict a non-empty bucket produces.
func TestBktDeleteBucketAnswers204(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucket", mock.Anything, mock.MatchedBy(func(in *s3.DeleteBucketInput) bool {
			return aws.ToString(in.Bucket) == bktBucket && in.ExpectedBucketOwner == nil
		})).Return(&s3.DeleteBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodDelete, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
		backend.AssertExpectations(t)
	})

	t.Run("expected_bucket_owner_is_forwarded", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucket", mock.Anything, mock.MatchedBy(func(in *s3.DeleteBucketInput) bool {
			return aws.ToString(in.ExpectedBucketOwner) == "123456789012"
		})).Return(&s3.DeleteBucketOutput{}, nil)
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodDelete, "/"+bktBucket, nil)
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		w := httptest.NewRecorder()
		h.Handle(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		backend.AssertExpectations(t)
	})

	t.Run("non_empty_bucket_is_a_conflict", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucket", mock.Anything, mock.Anything).
			Return(nil, BktapiError("BucketNotEmpty", ""))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodDelete, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusConflict, w.Code)
		doc := BktparseError(t, w.Body.Bytes())
		assert.Equal(t, "BucketNotEmpty", doc.Code)
		assert.Equal(t, "The bucket you tried to delete is not empty", doc.Message)
	})

	t.Run("missing_bucket_is_404", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("DeleteBucket", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchBucket", ""))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodDelete, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchBucket", BktparseError(t, w.Body.Bytes()).Code)
	})
}

// TestBktHeadBucketIsARealHeadBucket covers handleHeadBucket.
//
// It used to be a ListObjectsV2 with MaxKeys 0, which answers 200 for a bucket
// that does not exist - the backend short-circuits the listing before it checks
// that the bucket is there - and which asked for a listing permission a caller
// of HEAD may not have, so a backend allowing HeadBucket but denying ListBucket
// answered 403 for a bucket the client owns. ADR 0010 replaced it with the real
// operation, and the listing must not be reached at all.
func TestBktHeadBucketIsARealHeadBucket(t *testing.T) {
	t.Run("region_from_the_backend", func(t *testing.T) {
		backend := &MockS3Backend{}
		captured := BktcaptureHead(backend, &s3.HeadBucketOutput{BucketRegion: aws.String("eu-central-1")})
		h := BktnewHandlerWithConfig(backend, &config.Config{
			S3Backend: config.S3BackendConfig{Region: "us-east-1"},
		})

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
		assert.Equal(t, "eu-central-1", w.Header().Get("x-amz-bucket-region"),
			"the backend named a region, so the configured one does not apply")
		require.NotNil(t, *captured)
		assert.Equal(t, bktBucket, aws.ToString((*captured).Bucket))
		backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})

	t.Run("configured_region_when_the_backend_reports_none", func(t *testing.T) {
		// The normal path rather than a corner case: the development backend
		// returns no x-amz-bucket-region at all.
		backend := &MockS3Backend{}
		BktcaptureHead(backend, &s3.HeadBucketOutput{})
		h := BktnewHandlerWithConfig(backend, &config.Config{
			S3Backend: config.S3BackendConfig{Region: "us-east-1"},
		})

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "us-east-1", w.Header().Get("x-amz-bucket-region"))
		backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})

	t.Run("expected_bucket_owner_is_not_forwarded", func(t *testing.T) {
		// Recorded, not endorsed: the header reaches the handler and is dropped,
		// so a client using it as a guard is not guarded.
		backend := &MockS3Backend{}
		captured := BktcaptureHead(backend, &s3.HeadBucketOutput{})
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodHead, "/"+bktBucket, nil)
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		w := httptest.NewRecorder()
		h.Handle(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, *captured)
		assert.Nil(t, (*captured).ExpectedBucketOwner)
		// No region configured and none from the backend: the header is omitted
		// rather than sent empty.
		assert.Empty(t, w.Header().Get("x-amz-bucket-region"))
	})

	t.Run("missing_bucket_is_the_backend_error", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("HeadBucket", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchBucket", "The specified bucket does not exist"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, w.Header().Get("x-amz-bucket-region"))
		backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})

	t.Run("access_denied_is_forwarded", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("HeadBucket", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
		backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
	})
}

// errIsNotAnAPIError is a transport failure carrying the backend endpoint: the
// listing error path must map it to a generic 500 and keep the address out of
// the response.
var errIsNotAnAPIError = errBkt("dial tcp 10.9.9.9:9000: connect: connection refused")

type errBkt string

func (e errBkt) Error() string { return string(e) }

// BktfailingWriter is a ResponseWriter whose Write always fails, the shape a
// client that disconnects while the response is being streamed produces.
type BktfailingWriter struct {
	header http.Header
	code   int
}

func (w *BktfailingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *BktfailingWriter) Write([]byte) (int, error) {
	return 0, errBkt("client closed the connection")
}

func (w *BktfailingWriter) WriteHeader(code int) { w.code = code }

// BktclosingBody is a request body whose Close reports an error.
type BktclosingBody struct{ *strings.Reader }

func (BktclosingBody) Close() error { return errBkt("close failed") }

// TestBktResponseWriteFailuresAreLoggedNotPropagated covers the write-error arms
// of the listing and policy handlers. There is nothing left to say to a client
// that has gone away, so the only requirement is that the handler returns
// instead of panicking - and that a partial document is never rewritten with a
// different status.
//
// The listing document is marshalled BEFORE a status is committed, so 200 is on
// the wire before the body is attempted and a failed write cannot take it back.
// That order is what keeps a marshalling failure from becoming a truncated
// document behind a 200; the price is that a client disconnecting mid-body has
// already been told 200, which is what every S3 server does.
func TestBktResponseWriteFailuresAreLoggedNotPropagated(t *testing.T) {
	t.Run("list_objects_v2", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := &BktfailingWriter{}
		h.Handle(w, Bktrequest(http.MethodGet, "/"+bktBucket+"?list-type=2", nil))

		assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
		assert.Equal(t, http.StatusOK, w.code, "the status is committed before the body is written")
	})

	t.Run("list_objects_v1", func(t *testing.T) {
		backend := &MockS3Backend{}
		BktcaptureV1(backend, &s3.ListObjectsOutput{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String("a")}},
		})
		h := BktnewHandlerWith(backend)

		w := &BktfailingWriter{}
		h.Handle(w, Bktrequest(http.MethodGet, "/"+bktBucket, nil))

		assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
		assert.Equal(t, http.StatusOK, w.code)
	})

	t.Run("bucket_policy", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("GetBucketPolicy", mock.Anything, mock.Anything).
			Return(&s3.GetBucketPolicyOutput{Policy: aws.String(`{"Version":"2012-10-17"}`)}, nil)
		h := BktnewHandlerWith(backend)

		w := &BktfailingWriter{}
		h.GetPolicyHandler().Handle(w, Bktrequest(http.MethodGet, "/"+bktBucket+"?policy", nil))

		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// TestBktCreateBucketSurvivesABodyThatFailsToClose covers the Close error arm of
// handleCreateBucket: a body whose Close fails must not stop the bucket from
// being created, and must not turn into a client-visible error.
func TestBktCreateBucketSurvivesABodyThatFailsToClose(t *testing.T) {
	backend := &MockS3Backend{}
	backend.On("CreateBucket", mock.Anything, mock.MatchedBy(func(in *s3.CreateBucketInput) bool {
		return in.CreateBucketConfiguration != nil &&
			in.CreateBucketConfiguration.LocationConstraint == s3types.BucketLocationConstraintEuWest1
	})).Return(&s3.CreateBucketOutput{}, nil)
	h := BktnewHandlerWith(backend)

	body := `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	req := Bktrequest(http.MethodPut, "/"+bktBucket, nil)
	req.Body = BktclosingBody{strings.NewReader(body)}
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	h.Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	backend.AssertExpectations(t)
}

// TestBktListObjectsKeysWithXMLInvalidBytesSurviveEncodingType is what
// encoding-type is for, and the concrete consequence of dropping it.
//
// A key can hold bytes XML cannot represent. encoding/xml replaces each of them
// with U+FFFD, so a client that does not ask for encoding is served a key that
// does not exist and can never address the object it names - and that used to be
// every client, because the proxy dropped the parameter. Now the choice is the
// client's: ask for encoding-type=url and the bytes survive.
func TestBktListObjectsKeysWithXMLInvalidBytesSurviveEncodingType(t *testing.T) {
	const key = "reports/2026\x0cQ1\x01.pdf"
	// What the backend returns: the proxy always asks it for URL encoding.
	encoded := url.QueryEscape(key)

	readKey := func(t *testing.T, body []byte) string {
		t.Helper()
		var got struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
		}
		require.NoError(t, xml.Unmarshal(body, &got))
		require.Len(t, got.Contents, 1)
		return got.Contents[0].Key
	}

	t.Run("with_encoding_type_the_bytes_survive", func(t *testing.T) {
		backend := &MockS3Backend{}
		captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String(encoded)}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2&encoding-type=url")

		require.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, *captured)
		assert.Equal(t, s3types.EncodingTypeUrl, (*captured).EncodingType)
		assert.Contains(t, w.Body.String(), "%0C", "the invalid bytes are URL-encoded, not dropped")

		decoded, err := url.QueryUnescape(readKey(t, w.Body.Bytes()))
		require.NoError(t, err)
		assert.Equal(t, key, decoded, "the client can address the object it was shown")
	})

	t.Run("without_encoding_type_xml_still_loses_them", func(t *testing.T) {
		// Not a proxy defect and not fixable in the document: XML has no
		// representation for these bytes. S3 answers the same way, which is why
		// encoding-type exists and why forwarding it was the fix.
		backend := &MockS3Backend{}
		BktcaptureV2(backend, &s3.ListObjectsV2Output{
			Name:     aws.String(bktBucket),
			Contents: []s3types.Object{{Key: aws.String(encoded)}},
		})
		h := BktnewHandlerWith(backend)

		w := BktauthGet(h, "/"+bktBucket+"?list-type=2")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "reports/2026\uFFFDQ1\uFFFD.pdf", readKey(t, w.Body.Bytes()),
			"each XML-invalid byte became U+FFFD")
	})
}
