package object

import (
	"encoding/xml"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// The documents of the three passthrough object sub-resources (ADR 0007 D4),
// as this proxy's own types rather than the SDK's.
//
// The SDK's input and output structs carry no XML tags at all, so encoding/xml
// matches them by Go field name: a `<Tagging><TagSet><Tag>` body unmarshalled
// into `types.Tagging` binds nothing and yields an empty tag set, and marshalling
// `GetObjectTaggingOutput` produces a `<GetObjectTaggingOutput>` root no client
// reads. Both directions need a document of the proxy's own, the same conclusion
// the listing reached (ADR 0010).

// retainUntilFormat is what S3 emits for a retain-until date: RFC 3339 with
// exactly three fractional digits, as for a listing's LastModified.
const retainUntilFormat = "2006-01-02T15:04:05.000Z"

// taggingDocument is the body of GET and PUT /{bucket}/{key}?tagging.
type taggingDocument struct {
	XMLName xml.Name     `xml:"Tagging"`
	TagSet  tagSetHolder `xml:"TagSet"`
}

type tagSetHolder struct {
	Tags []tagDocument `xml:"Tag"`
}

type tagDocument struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// retentionDocument is the body of GET and PUT /{bucket}/{key}?retention.
type retentionDocument struct {
	XMLName         xml.Name `xml:"Retention"`
	Mode            string   `xml:"Mode,omitempty"`
	RetainUntilDate string   `xml:"RetainUntilDate,omitempty"`
}

// legalHoldDocument is the body of GET and PUT /{bucket}/{key}?legal-hold.
type legalHoldDocument struct {
	XMLName xml.Name `xml:"LegalHold"`
	Status  string   `xml:"Status,omitempty"`
}

func newTaggingDocument(tags []types.Tag) taggingDocument {
	doc := taggingDocument{}
	doc.TagSet.Tags = make([]tagDocument, 0, len(tags))
	for _, tag := range tags {
		doc.TagSet.Tags = append(doc.TagSet.Tags, tagDocument{
			Key:   aws.ToString(tag.Key),
			Value: aws.ToString(tag.Value),
		})
	}
	return doc
}

func (d taggingDocument) tagSet() []types.Tag {
	tags := make([]types.Tag, 0, len(d.TagSet.Tags))
	for _, tag := range d.TagSet.Tags {
		tags = append(tags, types.Tag{Key: aws.String(tag.Key), Value: aws.String(tag.Value)})
	}
	return tags
}

func newRetentionDocument(retention *types.ObjectLockRetention) retentionDocument {
	doc := retentionDocument{}
	if retention == nil {
		return doc
	}
	doc.Mode = string(retention.Mode)
	if retention.RetainUntilDate != nil {
		doc.RetainUntilDate = retention.RetainUntilDate.UTC().Format(retainUntilFormat)
	}
	return doc
}

// retention converts the parsed document back. A RetainUntilDate that is not a
// timestamp is an error rather than a silently dropped field.
func (d retentionDocument) retention() (*types.ObjectLockRetention, error) {
	retention := &types.ObjectLockRetention{Mode: types.ObjectLockRetentionMode(d.Mode)}
	if d.RetainUntilDate != "" {
		parsed, err := time.Parse(time.RFC3339, d.RetainUntilDate)
		if err != nil {
			return nil, err
		}
		retention.RetainUntilDate = aws.Time(parsed)
	}
	return retention, nil
}

func newLegalHoldDocument(hold *types.ObjectLockLegalHold) legalHoldDocument {
	if hold == nil {
		return legalHoldDocument{}
	}
	return legalHoldDocument{Status: string(hold.Status)}
}

func (d legalHoldDocument) legalHold() *types.ObjectLockLegalHold {
	return &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatus(d.Status)}
}
