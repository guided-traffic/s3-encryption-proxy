package object

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// StorageAttributes carries the storage headers ADR 0007 D3 forwards unchanged.
// None of them touches object content, so they are the client's business; what
// the decision forbids is accepting them and answering 200 without them ever
// reaching the backend.
//
// One struct, one reader and two appliers, because D3 requires the same answer
// on all three upload paths: a single-request PUT, the proxy's internal
// multipart producer and client-driven CreateMultipartUpload.
type StorageAttributes struct {
	ServerSideEncryption    string
	SSEKMSKeyID             string
	Tagging                 string
	StorageClass            string
	ACL                     string
	GrantFullControl        string
	GrantRead               string
	GrantReadACP            string
	GrantWriteACP           string
	ObjectLockMode          string
	ObjectLockRetainUntil   *time.Time
	ObjectLockLegalHold     string
	WebsiteRedirectLocation string
}

// sseCustomerHeaders are the three customer-key headers of ADR 0007 D6. No read
// path carries the key, so accepting one on upload would write an object this
// proxy could never read back.
var sseCustomerHeaders = []string{
	"x-amz-server-side-encryption-customer-algorithm",
	"x-amz-server-side-encryption-customer-key",
	"x-amz-server-side-encryption-customer-key-md5",
}

// SSECustomerHeader returns the first customer-key header present in h, or "".
func SSECustomerHeader(h http.Header) string {
	for _, name := range sseCustomerHeaders {
		if h.Get(name) != "" {
			return name
		}
	}
	return ""
}

// ReadStorageAttributes collects the forwarded storage headers of a request. A
// retain-until date that is not a timestamp is an error rather than a dropped
// header: silently storing an object with no retention is the shape ADR 0007 D1
// forbids.
func ReadStorageAttributes(r *http.Request) (StorageAttributes, error) {
	attrs := StorageAttributes{
		ServerSideEncryption:    r.Header.Get("x-amz-server-side-encryption"),
		SSEKMSKeyID:             r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"),
		Tagging:                 r.Header.Get("x-amz-tagging"),
		StorageClass:            r.Header.Get("x-amz-storage-class"),
		ACL:                     r.Header.Get("x-amz-acl"),
		GrantFullControl:        r.Header.Get("x-amz-grant-full-control"),
		GrantRead:               r.Header.Get("x-amz-grant-read"),
		GrantReadACP:            r.Header.Get("x-amz-grant-read-acp"),
		GrantWriteACP:           r.Header.Get("x-amz-grant-write-acp"),
		ObjectLockMode:          r.Header.Get("x-amz-object-lock-mode"),
		ObjectLockLegalHold:     r.Header.Get("x-amz-object-lock-legal-hold"),
		WebsiteRedirectLocation: r.Header.Get("x-amz-website-redirect-location"),
	}

	if raw := r.Header.Get("x-amz-object-lock-retain-until-date"); raw != "" {
		retainUntil, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return StorageAttributes{}, fmt.Errorf(
				"x-amz-object-lock-retain-until-date must be an RFC 3339 timestamp")
		}
		attrs.ObjectLockRetainUntil = &retainUntil
	}

	return attrs, nil
}

// ReadUploadHeaders collects everything an upload path takes from the request
// headers. It is the one reader all three paths use, so none of them can answer
// the same request differently (ADR 0007 D3). A header the proxy would have to
// parse and cannot is an error here, never a dropped header.
func ReadUploadHeaders(r *http.Request) (EntityHeaders, StorageAttributes, error) {
	entity, err := ReadEntityHeaders(r)
	if err != nil {
		return EntityHeaders{}, StorageAttributes{}, err
	}
	attrs, err := ReadStorageAttributes(r)
	if err != nil {
		return EntityHeaders{}, StorageAttributes{}, err
	}
	return entity, attrs, nil
}

// ApplyToPutObject sets the collected attributes on a single-request upload.
func (a StorageAttributes) ApplyToPutObject(input *s3.PutObjectInput) {
	input.ServerSideEncryption = types.ServerSideEncryption(a.ServerSideEncryption)
	input.StorageClass = types.StorageClass(a.StorageClass)
	input.ACL = types.ObjectCannedACL(a.ACL)
	input.ObjectLockMode = types.ObjectLockMode(a.ObjectLockMode)
	input.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatus(a.ObjectLockLegalHold)
	input.ObjectLockRetainUntilDate = a.ObjectLockRetainUntil

	input.SSEKMSKeyId = optionalString(a.SSEKMSKeyID)
	input.Tagging = optionalString(a.Tagging)
	input.GrantFullControl = optionalString(a.GrantFullControl)
	input.GrantRead = optionalString(a.GrantRead)
	input.GrantReadACP = optionalString(a.GrantReadACP)
	input.GrantWriteACP = optionalString(a.GrantWriteACP)
	input.WebsiteRedirectLocation = optionalString(a.WebsiteRedirectLocation)
}

// ApplyToCreateMultipartUpload sets the collected attributes on a multipart
// upload. The two SDK input types carry the same fields but are unrelated types,
// so the appliers cannot be one function.
func (a StorageAttributes) ApplyToCreateMultipartUpload(input *s3.CreateMultipartUploadInput) {
	input.ServerSideEncryption = types.ServerSideEncryption(a.ServerSideEncryption)
	input.StorageClass = types.StorageClass(a.StorageClass)
	input.ACL = types.ObjectCannedACL(a.ACL)
	input.ObjectLockMode = types.ObjectLockMode(a.ObjectLockMode)
	input.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatus(a.ObjectLockLegalHold)
	input.ObjectLockRetainUntilDate = a.ObjectLockRetainUntil

	input.SSEKMSKeyId = optionalString(a.SSEKMSKeyID)
	input.Tagging = optionalString(a.Tagging)
	input.GrantFullControl = optionalString(a.GrantFullControl)
	input.GrantRead = optionalString(a.GrantRead)
	input.GrantReadACP = optionalString(a.GrantReadACP)
	input.GrantWriteACP = optionalString(a.GrantWriteACP)
	input.WebsiteRedirectLocation = optionalString(a.WebsiteRedirectLocation)
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}

// EntityHeaders are the headers that describe the plaintext the client sent.
// They survive encryption unchanged and every upload path stores them.
type EntityHeaders struct {
	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string
	Expires            *time.Time
}

// ReadEntityHeaders collects them. Content-Encoding loses its aws-chunked token:
// that describes the request framing, which the proxy has already decoded, so
// storing it would mislabel the object. An Expires that is not an HTTP-date is
// an error rather than a dropped header, for the same reason as the retain-until
// date above.
func ReadEntityHeaders(r *http.Request) (EntityHeaders, error) {
	headers := EntityHeaders{
		ContentType:        r.Header.Get("Content-Type"),
		CacheControl:       r.Header.Get("Cache-Control"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
		ContentEncoding:    StripAWSChunked(r.Header.Get("Content-Encoding")),
		ContentLanguage:    r.Header.Get("Content-Language"),
	}

	if raw := r.Header.Get("Expires"); raw != "" {
		expires, err := http.ParseTime(raw)
		if err != nil {
			return EntityHeaders{}, fmt.Errorf("Expires must be an HTTP-date")
		}
		headers.Expires = &expires
	}

	return headers, nil
}

// ApplyToPutObject sets the entity headers on a single-request upload.
func (e EntityHeaders) ApplyToPutObject(input *s3.PutObjectInput) {
	input.ContentType = optionalString(e.ContentType)
	input.CacheControl = optionalString(e.CacheControl)
	input.ContentDisposition = optionalString(e.ContentDisposition)
	input.ContentEncoding = optionalString(e.ContentEncoding)
	input.ContentLanguage = optionalString(e.ContentLanguage)
	input.Expires = e.Expires
}

// ApplyToCreateMultipartUpload sets the entity headers on a multipart upload.
func (e EntityHeaders) ApplyToCreateMultipartUpload(input *s3.CreateMultipartUploadInput) {
	input.ContentType = optionalString(e.ContentType)
	input.CacheControl = optionalString(e.CacheControl)
	input.ContentDisposition = optionalString(e.ContentDisposition)
	input.ContentEncoding = optionalString(e.ContentEncoding)
	input.ContentLanguage = optionalString(e.ContentLanguage)
	input.Expires = e.Expires
}
