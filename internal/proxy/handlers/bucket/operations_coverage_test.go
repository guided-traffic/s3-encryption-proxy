package bucket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

// TestBktListObjectsV2DocumentIsNotAListBucketResult confirms the defect
// ADR 0010 describes, over the exact bytes a client receives.
//
// Pins the current behaviour. ADR 0010 replaces this document; update together.
func TestBktListObjectsV2DocumentIsNotAListBucketResult(t *testing.T) {
	modified := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:        aws.String(bktBucket),
		Prefix:      aws.String("docs/"),
		KeyCount:    aws.Int32(1),
		MaxKeys:     aws.Int32(1000),
		IsTruncated: aws.Bool(false),
		Contents: []s3types.Object{{
			Key:               aws.String("docs/report.pdf"),
			Size:              aws.Int64(1_048_604),
			LastModified:      &modified,
			ETag:              aws.String(`"ciphertext-etag"`),
			StorageClass:      s3types.ObjectStorageClassStandard,
			ChecksumAlgorithm: []s3types.ChecksumAlgorithm{s3types.ChecksumAlgorithmCrc32},
		}},
		CommonPrefixes: []s3types.CommonPrefix{{Prefix: aws.String("docs/archive/")}},
	})
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2&prefix=docs/&delimiter=/", nil)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	body := w.Body.String()

	// What S3 documents, and what a strict client or an XSD validator expects.
	assert.NotContains(t, body, "<ListBucketResult", "S3 names the root element ListBucketResult")
	assert.NotContains(t, body, `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`, "no S3 namespace")
	assert.False(t, strings.HasPrefix(body, xml.Header), "no XML prolog")

	// What the proxy actually sends: the aws-sdk-go-v2 output struct, marshalled
	// by field name.
	assert.True(t, strings.HasPrefix(body, "<ListObjectsV2Output>"), "actual root element: %s", body)
	assert.Contains(t, body, "<ResultMetadata></ResultMetadata>", "SDK-internal element leaks into the wire document")
	assert.Contains(t, body, "<RequestCharged></RequestCharged>", "element S3 never emits in a listing")
	assert.Contains(t, body, "<EncodingType></EncodingType>", "empty element S3 omits entirely")
	assert.Contains(t, body, "<ChecksumType></ChecksumType>", "per-object element S3 only emits when asked")

	// The parts a client does need are present, so aws-sdk-go-v2 and minio-go
	// keep working: they match elements by local name and ignore the root.
	assert.Contains(t, body, "<Key>docs/report.pdf</Key>")
	assert.Contains(t, body, "<LastModified>2026-03-04T05:06:07Z</LastModified>")
	assert.Contains(t, body, "<CommonPrefixes><Prefix>docs/archive/</Prefix></CommonPrefixes>")

	// The backend's checksum algorithm describes the CIPHERTEXT and is forwarded
	// as if it described what the client will receive.
	assert.Contains(t, body, "<ChecksumAlgorithm>CRC32</ChecksumAlgorithm>")
	// The backend's ETag likewise: it is the MD5 of the stored ciphertext.
	assert.Contains(t, body, `<ETag>&#34;ciphertext-etag&#34;</ETag>`)
}

// TestBktListObjectsReportsTheStoredCiphertextSize is the <Size> half of
// ADR 0010, pinned as a pure pass-through: whatever number the backend
// reports for the stored object is what the client is told, with no adjustment
// for the encryption overhead the proxy itself added.
//
// Pins the current behaviour. ADR 0003 and ADR 0010 change this; update together.
func TestBktListObjectsReportsTheStoredCiphertextSize(t *testing.T) {
	// 1 MiB of plaintext stored as AES-GCM costs 28 bytes of nonce plus tag.
	const plaintextSize = 1 << 20
	const storedSize = plaintextSize + 28

	backend := &MockS3Backend{}
	BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name: aws.String(bktBucket),
		Contents: []s3types.Object{
			{Key: aws.String("a"), Size: aws.Int64(storedSize)},
			{Key: aws.String("empty"), Size: aws.Int64(28)},
		},
	})
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2", nil)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "<Size>"+strconv.Itoa(storedSize)+"</Size>",
		"the listing reports the ciphertext size, not the %d bytes a GET returns", plaintextSize)
	assert.NotContains(t, body, "<Size>"+strconv.Itoa(plaintextSize)+"</Size>")
	// A zero-byte object is listed as 28 bytes, so a client that treats size 0
	// as "empty" never sees an empty object through this proxy.
	assert.Contains(t, body, "<Size>28</Size>")
}

// TestBktListObjectsV2ParameterHandling walks every listing parameter a client
// can send and asserts exactly which of them reach the backend. The dropped
// ones are the ADR 0010 finding; start-after in particular means a
// client that pages with StartAfter is served the same first page forever.
//
// Pins the current behaviour. ADR 0010 changes this; update together.
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
		// Dropped parameters.
		{"start_after_is_dropped", "start-after=key-500", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.StartAfter, "start-after never reaches the backend: paging with it loops forever")
		}},
		{"fetch_owner_is_dropped", "fetch-owner=true", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Nil(t, in.FetchOwner, "the client asked for <Owner> and gets no owner elements")
		}},
		{"encoding_type_is_dropped", "encoding-type=url", func(t *testing.T, in *s3.ListObjectsV2Input) {
			assert.Empty(t, string(in.EncodingType), "keys are returned raw whatever the client asked for")
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

			w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2&"+tc.query, nil)

			require.Equal(t, http.StatusOK, w.Code)
			require.NotNil(t, *captured)
			assert.Equal(t, bktBucket, aws.ToString((*captured).Bucket))
			tc.check(t, *captured)
		})
	}
}

// TestBktListObjectsV2MaxKeysBoundaries pins the accepted range and what
// happens on each side of it. Out-of-range and unparseable values are dropped
// silently, so a client that asks for 0 keys or sends a negative number is
// served a full page instead of an answer or an InvalidArgument.
//
// Pins the current behaviour. ADR 0010 changes this; update together.
func TestBktListObjectsV2MaxKeysBoundaries(t *testing.T) {
	cases := []struct {
		value    string
		wantSet  bool
		wantKeys int32
		note     string
	}{
		{"1", true, 1, "lower bound"},
		{"2", true, 2, "just inside"},
		{"999", true, 999, "just inside the upper bound"},
		{"1000", true, 1000, "upper bound"},
		{"1001", false, 0, "one past the bound: dropped, so the backend default applies"},
		{"0", false, 0, "AWS returns an empty listing; here the parameter is dropped"},
		{"-1", false, 0, "AWS answers InvalidArgument; here the parameter is dropped"},
		{"5000", false, 0, "AWS clamps to 1000; here the parameter is dropped"},
		{"abc", false, 0, "AWS answers InvalidArgument; here the parameter is dropped"},
		{"", false, 0, "absent"},
		{"9223372036854775808", false, 0, "int64 overflow: dropped, not a crash"},
	}

	for _, tc := range cases {
		t.Run("max-keys="+tc.value, func(t *testing.T) {
			backend := &MockS3Backend{}
			captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
			h := BktnewHandlerWith(backend)

			w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2&max-keys="+tc.value, nil)

			require.Equal(t, http.StatusOK, w.Code, tc.note)
			require.NotNil(t, *captured)
			if tc.wantSet {
				require.NotNil(t, (*captured).MaxKeys, tc.note)
				assert.Equal(t, tc.wantKeys, *(*captured).MaxKeys, tc.note)
			} else {
				assert.Nil(t, (*captured).MaxKeys, tc.note)
			}
		})
	}
}

// TestBktListObjectsV1ParameterHandling is the same walk for the V1 listing,
// which the aws CLI still uses for `s3api list-objects` and which drops even
// max-keys.
//
// Pins the current behaviour. ADR 0010 changes this; update together.
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
		{"max_keys_is_dropped_entirely", "max-keys=1", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Nil(t, in.MaxKeys, "the V1 branch never reads max-keys: a client asking for 1 key gets a full page")
		}},
		{"encoding_type_is_dropped", "encoding-type=url", func(t *testing.T, in *s3.ListObjectsInput) {
			assert.Empty(t, string(in.EncodingType))
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

			w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?"+tc.query, nil)

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
			w := Bktserve(h.Handle, http.MethodGet, url, nil)

			require.Equal(t, http.StatusOK, w.Code, "list-type=%q", listType)
			backend.AssertCalled(t, "ListObjects", mock.Anything, mock.Anything)
			backend.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
			assert.True(t, strings.HasPrefix(w.Body.String(), "<ListObjectsOutput>"))
		}
	})
}

// TestBktListObjectsEmptyBucketIsAWellFormedDocument covers the boundary a
// client hits most often after CreateBucket.
func TestBktListObjectsEmptyBucketIsAWellFormedDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		root string
	}{
		{"v2", "/" + bktBucket + "?list-type=2", "ListObjectsV2Output"},
		{"v1", "/" + bktBucket, "ListObjectsOutput"},
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

			w := Bktserve(h.Handle, http.MethodGet, tc.url, nil)

			require.Equal(t, http.StatusOK, w.Code)
			assert.True(t, strings.HasPrefix(w.Body.String(), "<"+tc.root+">"))
			assert.NotContains(t, w.Body.String(), "<Contents>")
			var probe struct {
				Name string `xml:"Name"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &probe), "the document must at least parse")
			assert.Equal(t, bktBucket, probe.Name)
		})
	}
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

// TestBktListObjectsBackendErrors covers the error arm of both listing
// branches, which goes through utils.HandleS3Error rather than the sub-resource
// error writer.
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

// TestBktHeadBucketIsImplementedAsAListing covers handleHeadBucket and records
// what that costs a client. ADR 0010 decides that HeadBucket stops being
// implemented as a listing and becomes a real bucket existence check.
//
// Pins the current behaviour. ADR 0010 replaces this; update together.
func TestBktHeadBucketIsImplementedAsAListing(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		backend := &MockS3Backend{}
		captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{Name: aws.String(bktBucket)})
		h := BktnewHandlerWith(backend)

		req := Bktrequest(http.MethodHead, "/"+bktBucket, nil)
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		w := httptest.NewRecorder()
		h.Handle(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
		// It never calls the backend's HeadBucket, so a backend that allows
		// HeadBucket but denies ListBucket answers 403 for an existing bucket.
		backend.AssertNotCalled(t, "HeadBucket", mock.Anything, mock.Anything)
		require.NotNil(t, *captured)
		require.NotNil(t, (*captured).MaxKeys)
		assert.Equal(t, int32(0), *(*captured).MaxKeys)
		// x-amz-expected-bucket-owner is parsed by no one on this path.
		assert.Nil(t, (*captured).ExpectedBucketOwner)
		// AWS answers HeadBucket with x-amz-bucket-region; the proxy sends none.
		assert.Empty(t, w.Header().Get("x-amz-bucket-region"))
	})

	t.Run("missing_bucket_is_404", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("ListObjectsV2", mock.Anything, mock.Anything).
			Return(nil, BktapiError("NoSuchBucket", ""))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("list_permission_denied_looks_like_a_forbidden_bucket", func(t *testing.T) {
		backend := &MockS3Backend{}
		backend.On("ListObjectsV2", mock.Anything, mock.Anything).
			Return(nil, BktapiError("AccessDenied", "Access Denied"))
		h := BktnewHandlerWith(backend)

		w := Bktserve(h.Handle, http.MethodHead, "/"+bktBucket, nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
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
		assert.Zero(t, w.code, "the status was never explicitly set, so net/http would have sent 200")
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

// TestBktListObjectsCorruptsKeysWithXMLInvalidBytes is the concrete consequence
// of dropping encoding-type. A client sends encoding-type=url precisely so that
// keys containing bytes XML cannot represent survive the listing; the proxy
// drops the parameter and marshals the raw key, and encoding/xml replaces each
// offending byte with U+FFFD. The client is served a key that does not exist and
// can never address the object it names.
//
// Pins the current behaviour. ADR 0010 changes this; update together.
func TestBktListObjectsCorruptsKeysWithXMLInvalidBytes(t *testing.T) {
	const stored = "reports/2026\x0cQ1\x01.pdf"

	backend := &MockS3Backend{}
	captured := BktcaptureV2(backend, &s3.ListObjectsV2Output{
		Name:     aws.String(bktBucket),
		Contents: []s3types.Object{{Key: aws.String(stored)}},
	})
	h := BktnewHandlerWith(backend)

	w := Bktserve(h.Handle, http.MethodGet, "/"+bktBucket+"?list-type=2&encoding-type=url", nil)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, *captured)
	assert.Empty(t, string((*captured).EncodingType), "the client asked for URL encoding and did not get it")

	var got struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Contents, 1)
	assert.NotEqual(t, stored, got.Contents[0].Key, "the key the client receives is not the key that is stored")
	assert.Equal(t, "reports/2026�Q1�.pdf", got.Contents[0].Key,
		"each XML-invalid byte became U+FFFD")
	assert.NotContains(t, w.Body.String(), "%0C", "no URL encoding was applied")
}
