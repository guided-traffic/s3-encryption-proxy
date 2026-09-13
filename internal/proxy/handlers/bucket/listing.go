package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// handleListObjects answers GET /{bucket} for both listing versions.
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Listing objects in bucket")

	if r.URL.Query().Get("list-type") == "2" {
		h.listObjectsV2(w, r, bucket)
		return
	}
	h.listObjectsV1(w, r, bucket)
}

// reportedSize is the size a listing states for one stored object.
//
// Under an encrypting provider the proxy reports the plaintext length, computed
// from the stored length by arithmetic it controls — no metadata, no round trip
// (ADR 0010). A stored size that cannot be one this proxy wrote is reported
// verbatim: the entry is a foreign object, and inventing a length for it would
// be worse than under-reporting it.
func (h *Handler) reportedSize(stored int64, encrypting bool) int64 {
	if !encrypting {
		return stored
	}
	plaintext, err := dataencryption.PlaintextSize(stored)
	if err != nil {
		return stored
	}
	return plaintext
}

// activeProviderEncrypts reports whether the active provider encrypts. A nil
// manager means the handler was built without one, which only happens in tests
// that do not exercise a listing size.
func (h *Handler) activeProviderEncrypts() bool {
	return h.encryptionMgr != nil && !h.encryptionMgr.IsExitProvider()
}

// callerOwner describes the authenticated client. S3 puts an opaque canonical id
// in <Owner>; the proxy has none for its own clients and answers with the access
// key, which is the only identity it actually knows (ADR 0008).
func callerOwner(r *http.Request) *ownerEntry {
	id := middleware.ClientIdentity(r.Context())
	if id == "" {
		return nil
	}
	return &ownerEntry{ID: id, DisplayName: id}
}

func (h *Handler) listObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	query := r.URL.Query()

	maxKeys, err := parseMaxKeys(query.Get("max-keys"))
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	wantsEncoding := clientWantsURLEncoding(query.Get("encoding-type"))
	fetchOwner := query.Get("fetch-owner") == "true"

	input := &s3.ListObjectsV2Input{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		// Always ask the backend for URL encoding, whatever the client wanted:
		// it makes the backend's XML well formed no matter what bytes a key
		// contains. The proxy decodes below and re-encodes only if asked.
		EncodingType: s3types.EncodingTypeUrl,
		MaxKeys:      maxKeys,
	}
	if v := query.Get("prefix"); v != "" {
		input.Prefix = aws.String(v)
	}
	if v := query.Get("delimiter"); v != "" {
		input.Delimiter = aws.String(v)
	}
	if v := query.Get("continuation-token"); v != "" {
		input.ContinuationToken = aws.String(v)
	}
	if v := query.Get("start-after"); v != "" {
		input.StartAfter = aws.String(v)
	}
	if fetchOwner {
		input.FetchOwner = aws.Bool(true)
	}

	output, err := h.s3Backend.ListObjectsV2(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	encrypting := h.activeProviderEncrypts()
	owner := callerOwner(r)

	doc := listBucketResultV2{
		Name:        bucket,
		Prefix:      encodeForClient(decodeBackendValue(aws.ToString(output.Prefix)), wantsEncoding),
		StartAfter:  encodeForClient(decodeBackendValue(aws.ToString(output.StartAfter)), wantsEncoding),
		Delimiter:   encodeForClient(decodeBackendValue(aws.ToString(output.Delimiter)), wantsEncoding),
		IsTruncated: aws.ToBool(output.IsTruncated),
		KeyCount:    aws.ToInt32(output.KeyCount),
		MaxKeys:     aws.ToInt32(output.MaxKeys),
		// The tokens are opaque and already safe for a URL; they are forwarded
		// verbatim in both directions rather than decoded and re-encoded.
		ContinuationToken:     aws.ToString(output.ContinuationToken),
		NextContinuationToken: aws.ToString(output.NextContinuationToken),
	}
	if wantsEncoding {
		doc.EncodingType = "url"
	}

	for i := range output.Contents {
		entry := &output.Contents[i]
		item := objectEntry{
			Key:          encodeForClient(decodeBackendValue(aws.ToString(entry.Key)), wantsEncoding),
			LastModified: formatLastModified(entry.LastModified),
			ETag:         aws.ToString(entry.ETag),
			Size:         h.reportedSize(aws.ToInt64(entry.Size), encrypting),
			StorageClass: string(entry.StorageClass),
		}
		if fetchOwner {
			item.Owner = owner
		}
		doc.Contents = append(doc.Contents, item)
	}

	for i := range output.CommonPrefixes {
		p := aws.ToString(output.CommonPrefixes[i].Prefix)
		doc.CommonPrefixes = append(doc.CommonPrefixes, commonPrefix{
			Prefix: encodeForClient(decodeBackendValue(p), wantsEncoding),
		})
	}

	h.xmlWriter.WriteS3Document(w, doc)
}

func (h *Handler) listObjectsV1(w http.ResponseWriter, r *http.Request, bucket string) {
	query := r.URL.Query()

	maxKeys, err := parseMaxKeys(query.Get("max-keys"))
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	wantsEncoding := clientWantsURLEncoding(query.Get("encoding-type"))

	input := &s3.ListObjectsInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		EncodingType:        s3types.EncodingTypeUrl,
		MaxKeys:             maxKeys,
	}
	if v := query.Get("prefix"); v != "" {
		input.Prefix = aws.String(v)
	}
	if v := query.Get("delimiter"); v != "" {
		input.Delimiter = aws.String(v)
	}
	if v := query.Get("marker"); v != "" {
		input.Marker = aws.String(v)
	}

	output, err := h.s3Backend.ListObjects(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	encrypting := h.activeProviderEncrypts()
	owner := callerOwner(r)

	doc := listBucketResultV1{
		Name:        bucket,
		Prefix:      encodeForClient(decodeBackendValue(aws.ToString(output.Prefix)), wantsEncoding),
		Marker:      encodeForClient(decodeBackendValue(aws.ToString(output.Marker)), wantsEncoding),
		NextMarker:  encodeForClient(decodeBackendValue(aws.ToString(output.NextMarker)), wantsEncoding),
		Delimiter:   encodeForClient(decodeBackendValue(aws.ToString(output.Delimiter)), wantsEncoding),
		MaxKeys:     aws.ToInt32(output.MaxKeys),
		IsTruncated: aws.ToBool(output.IsTruncated),
	}
	if wantsEncoding {
		doc.EncodingType = "url"
	}

	for i := range output.Contents {
		entry := &output.Contents[i]
		doc.Contents = append(doc.Contents, objectEntry{
			Key:          encodeForClient(decodeBackendValue(aws.ToString(entry.Key)), wantsEncoding),
			LastModified: formatLastModified(entry.LastModified),
			ETag:         aws.ToString(entry.ETag),
			Size:         h.reportedSize(aws.ToInt64(entry.Size), encrypting),
			// V1 carries the owner without being asked, which is what S3 does.
			Owner:        owner,
			StorageClass: string(entry.StorageClass),
		})
	}

	for i := range output.CommonPrefixes {
		p := aws.ToString(output.CommonPrefixes[i].Prefix)
		doc.CommonPrefixes = append(doc.CommonPrefixes, commonPrefix{
			Prefix: encodeForClient(decodeBackendValue(p), wantsEncoding),
		})
	}

	h.xmlWriter.WriteS3Document(w, doc)
}
