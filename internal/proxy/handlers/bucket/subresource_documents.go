package bucket

import (
	"encoding/xml"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// The response documents of the bucket sub-resources, as this proxy's own types.
//
// Every sub-resource GET used to hand the aws-sdk-go-v2 **output struct** to the
// XML writer. Those structs carry no XML tags, so encoding/xml named every
// element after its Go field: `GET /{bucket}?cors` answered
//
//	<GetBucketCorsOutput><CORSRules><AllowedMethods>GET</AllowedMethods>...
//	  <ResultMetadata></ResultMetadata></GetBucketCorsOutput>
//
// where S3 answers `<CORSConfiguration><CORSRule><AllowedMethod>`. No S3 client
// could parse any of the twenty-one, and the SDK's internal ResultMetadata
// leaked into every one of them. Same root cause as the listing (ADR 0010), one
// level out: a response describes the proxy, so the proxy owns the document
// (ADR 0008).
//
// Element names are taken from the SDK's own deserializers, which are the wire
// names S3 uses, not from the field names of its structs.

// s3Namespace is the document namespace S3 puts on every response.
const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// retainDateFormat is what S3 emits for a date inside a configuration document.
const retainDateFormat = "2006-01-02T15:04:05.000Z"

func formatDate(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(retainDateFormat)
}

// ---------------------------------------------------------------------------
// Shared leaves
// ---------------------------------------------------------------------------

type ownerDocument struct {
	ID          string `xml:"ID,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

// granteeDocument carries the xsi:type attribute S3 uses to say which kind of
// grantee this is. The instance namespace has to be declared on the element,
// because nothing above it declares one.
//
// The attribute needs two fields, one per direction. encoding/xml writes the
// literal prefix of `xsi:type`, which is what a client has to read; but on the
// way in the decoder has already resolved that prefix against the document's
// xmlns:xsi declaration, so the literal tag never matches and ResolvedType is
// what catches it. A client that sends `xsi:type` without declaring the prefix
// is caught by the literal field instead. Both are omitempty, so marshalling
// emits exactly one.
type granteeDocument struct {
	XMLNSXSI     string `xml:"xmlns:xsi,attr,omitempty"`
	Type         string `xml:"xsi:type,attr,omitempty"`
	ResolvedType string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr,omitempty"`
	ID           string `xml:"ID,omitempty"`
	DisplayName  string `xml:"DisplayName,omitempty"`
	EmailAddress string `xml:"EmailAddress,omitempty"`
	URI          string `xml:"URI,omitempty"`
}

// granteeType is the attribute whichever way it arrived.
func (g *granteeDocument) granteeType() string {
	if g.ResolvedType != "" {
		return g.ResolvedType
	}
	return g.Type
}

type grantDocument struct {
	Grantee    *granteeDocument `xml:"Grantee,omitempty"`
	Permission string           `xml:"Permission,omitempty"`
}

type tagDocument struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

func newOwnerDocument(owner *types.Owner) *ownerDocument {
	if owner == nil {
		return nil
	}
	return &ownerDocument{ID: aws.ToString(owner.ID), DisplayName: aws.ToString(owner.DisplayName)}
}

func newGranteeDocument(grantee *types.Grantee) *granteeDocument {
	if grantee == nil {
		return nil
	}
	return &granteeDocument{
		XMLNSXSI:     "http://www.w3.org/2001/XMLSchema-instance",
		Type:         string(grantee.Type),
		ID:           aws.ToString(grantee.ID),
		DisplayName:  aws.ToString(grantee.DisplayName),
		EmailAddress: aws.ToString(grantee.EmailAddress),
		URI:          aws.ToString(grantee.URI),
	}
}

func newTagDocuments(tags []types.Tag) []tagDocument {
	docs := make([]tagDocument, 0, len(tags))
	for _, tag := range tags {
		docs = append(docs, tagDocument{Key: aws.ToString(tag.Key), Value: aws.ToString(tag.Value)})
	}
	return docs
}

func tagSetFromDocuments(docs []tagDocument) []types.Tag {
	tags := make([]types.Tag, 0, len(docs))
	for _, doc := range docs {
		tags = append(tags, types.Tag{Key: aws.String(doc.Key), Value: aws.String(doc.Value)})
	}
	return tags
}

// ---------------------------------------------------------------------------
// ?acl
// ---------------------------------------------------------------------------

// accessControlPolicyDocument is the ?acl document in both directions: it is what
// GET answers, and what PUT parses. The SDK's own AccessControlPolicy is tagless,
// so `<AccessControlList><Grant>` bound to nothing and every grant a client sent
// was discarded before the backend was addressed (ADR 0007 D5).
type accessControlPolicyDocument struct {
	XMLName           xml.Name             `xml:"AccessControlPolicy"`
	XMLNS             string               `xml:"xmlns,attr,omitempty"`
	Owner             *ownerDocument       `xml:"Owner,omitempty"`
	AccessControlList *accessControlListPD `xml:"AccessControlList,omitempty"`
}

type accessControlListPD struct {
	Grants []grantDocument `xml:"Grant"`
}

func newAccessControlPolicyDocument(output *s3.GetBucketAclOutput) accessControlPolicyDocument {
	doc := accessControlPolicyDocument{XMLNS: s3Namespace, Owner: newOwnerDocument(output.Owner)}
	list := &accessControlListPD{Grants: make([]grantDocument, 0, len(output.Grants))}
	for _, grant := range output.Grants {
		list.Grants = append(list.Grants, grantDocument{
			Grantee:    newGranteeDocument(grant.Grantee),
			Permission: string(grant.Permission),
		})
	}
	doc.AccessControlList = list
	return doc
}

// accessControlPolicy converts a parsed document into the SDK type the backend
// call takes.
func (d accessControlPolicyDocument) accessControlPolicy() *types.AccessControlPolicy {
	policy := &types.AccessControlPolicy{}
	if d.Owner != nil {
		policy.Owner = &types.Owner{
			ID:          aws.String(d.Owner.ID),
			DisplayName: aws.String(d.Owner.DisplayName),
		}
	}
	if d.AccessControlList == nil {
		return policy
	}
	policy.Grants = make([]types.Grant, 0, len(d.AccessControlList.Grants))
	for _, grant := range d.AccessControlList.Grants {
		converted := types.Grant{Permission: types.Permission(grant.Permission)}
		if grant.Grantee != nil {
			converted.Grantee = &types.Grantee{
				Type:         types.Type(grant.Grantee.granteeType()),
				ID:           aws.String(grant.Grantee.ID),
				DisplayName:  aws.String(grant.Grantee.DisplayName),
				EmailAddress: aws.String(grant.Grantee.EmailAddress),
				URI:          aws.String(grant.Grantee.URI),
			}
		}
		policy.Grants = append(policy.Grants, converted)
	}
	return policy
}

// ---------------------------------------------------------------------------
// ?cors
// ---------------------------------------------------------------------------

type corsConfigurationDocument struct {
	XMLName xml.Name           `xml:"CORSConfiguration"`
	XMLNS   string             `xml:"xmlns,attr,omitempty"`
	Rules   []corsRuleDocument `xml:"CORSRule"`
}

type corsRuleDocument struct {
	ID             string   `xml:"ID,omitempty"`
	AllowedHeaders []string `xml:"AllowedHeader,omitempty"`
	AllowedMethods []string `xml:"AllowedMethod"`
	AllowedOrigins []string `xml:"AllowedOrigin"`
	ExposeHeaders  []string `xml:"ExposeHeader,omitempty"`
	MaxAgeSeconds  *int32   `xml:"MaxAgeSeconds,omitempty"`
}

func newCORSConfigurationDocument(rules []types.CORSRule) corsConfigurationDocument {
	doc := corsConfigurationDocument{XMLNS: s3Namespace, Rules: make([]corsRuleDocument, 0, len(rules))}
	for _, rule := range rules {
		doc.Rules = append(doc.Rules, corsRuleDocument{
			ID:             aws.ToString(rule.ID),
			AllowedHeaders: rule.AllowedHeaders,
			AllowedMethods: rule.AllowedMethods,
			AllowedOrigins: rule.AllowedOrigins,
			ExposeHeaders:  rule.ExposeHeaders,
			MaxAgeSeconds:  rule.MaxAgeSeconds,
		})
	}
	return doc
}

func (d corsConfigurationDocument) corsConfiguration() *types.CORSConfiguration {
	config := &types.CORSConfiguration{CORSRules: make([]types.CORSRule, 0, len(d.Rules))}
	for _, rule := range d.Rules {
		config.CORSRules = append(config.CORSRules, types.CORSRule{
			ID:             optional(rule.ID),
			AllowedHeaders: rule.AllowedHeaders,
			AllowedMethods: rule.AllowedMethods,
			AllowedOrigins: rule.AllowedOrigins,
			ExposeHeaders:  rule.ExposeHeaders,
			MaxAgeSeconds:  rule.MaxAgeSeconds,
		})
	}
	return config
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}

// ---------------------------------------------------------------------------
// The single-element documents
// ---------------------------------------------------------------------------

type accelerateConfigurationDocument struct {
	XMLName xml.Name `xml:"AccelerateConfiguration"`
	XMLNS   string   `xml:"xmlns,attr,omitempty"`
	Status  string   `xml:"Status,omitempty"`
}

type requestPaymentConfigurationDocument struct {
	XMLName xml.Name `xml:"RequestPaymentConfiguration"`
	XMLNS   string   `xml:"xmlns,attr,omitempty"`
	Payer   string   `xml:"Payer,omitempty"`
}

// locationConstraintDocument is the one sub-resource whose whole document is a
// single element with the value as its text.
type locationConstraintDocument struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	XMLNS   string   `xml:"xmlns,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type versioningConfigurationDocument struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	Status    string   `xml:"Status,omitempty"`
	MfaDelete string   `xml:"MfaDelete,omitempty"`
}

type taggingDocument struct {
	XMLName xml.Name       `xml:"Tagging"`
	XMLNS   string         `xml:"xmlns,attr,omitempty"`
	TagSet  tagSetDocument `xml:"TagSet"`
}

type tagSetDocument struct {
	Tags []tagDocument `xml:"Tag"`
}

// ---------------------------------------------------------------------------
// ?logging
// ---------------------------------------------------------------------------

type bucketLoggingStatusDocument struct {
	XMLName        xml.Name                `xml:"BucketLoggingStatus"`
	XMLNS          string                  `xml:"xmlns,attr,omitempty"`
	LoggingEnabled *loggingEnabledDocument `xml:"LoggingEnabled,omitempty"`
}

type loggingEnabledDocument struct {
	TargetBucket string          `xml:"TargetBucket"`
	TargetPrefix string          `xml:"TargetPrefix"`
	TargetGrants *targetGrantsPD `xml:"TargetGrants,omitempty"`
}

type targetGrantsPD struct {
	Grants []grantDocument `xml:"Grant"`
}

func newBucketLoggingStatusDocument(enabled *types.LoggingEnabled) bucketLoggingStatusDocument {
	doc := bucketLoggingStatusDocument{XMLNS: s3Namespace}
	if enabled == nil {
		return doc
	}
	logging := &loggingEnabledDocument{
		TargetBucket: aws.ToString(enabled.TargetBucket),
		TargetPrefix: aws.ToString(enabled.TargetPrefix),
	}
	if len(enabled.TargetGrants) > 0 {
		grants := &targetGrantsPD{Grants: make([]grantDocument, 0, len(enabled.TargetGrants))}
		for _, grant := range enabled.TargetGrants {
			grants.Grants = append(grants.Grants, grantDocument{
				Grantee:    newGranteeDocument(grant.Grantee),
				Permission: string(grant.Permission),
			})
		}
		logging.TargetGrants = grants
	}
	doc.LoggingEnabled = logging
	return doc
}

// ---------------------------------------------------------------------------
// ?lifecycle
// ---------------------------------------------------------------------------

type lifecycleConfigurationDocument struct {
	XMLName xml.Name                `xml:"LifecycleConfiguration"`
	XMLNS   string                  `xml:"xmlns,attr,omitempty"`
	Rules   []lifecycleRuleDocument `xml:"Rule"`
}

type lifecycleRuleDocument struct {
	ID                             string                         `xml:"ID,omitempty"`
	Status                         string                         `xml:"Status,omitempty"`
	Prefix                         string                         `xml:"Prefix,omitempty"`
	Filter                         *lifecycleFilterDocument       `xml:"Filter,omitempty"`
	Expiration                     *lifecycleExpirationDocument   `xml:"Expiration,omitempty"`
	Transitions                    []transitionDocument           `xml:"Transition,omitempty"`
	NoncurrentVersionTransitions   []noncurrentTransitionDocument `xml:"NoncurrentVersionTransition,omitempty"`
	NoncurrentVersionExpiration    *noncurrentExpirationDocument  `xml:"NoncurrentVersionExpiration,omitempty"`
	AbortIncompleteMultipartUpload *abortIncompleteUploadDocument `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

type lifecycleFilterDocument struct {
	Prefix                string                `xml:"Prefix,omitempty"`
	Tag                   *tagDocument          `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan *int64                `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64                `xml:"ObjectSizeLessThan,omitempty"`
	And                   *lifecycleAndDocument `xml:"And,omitempty"`
}

type lifecycleAndDocument struct {
	Prefix                string        `xml:"Prefix,omitempty"`
	Tags                  []tagDocument `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan *int64        `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64        `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleExpirationDocument struct {
	Date                      string `xml:"Date,omitempty"`
	Days                      *int32 `xml:"Days,omitempty"`
	ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker,omitempty"`
}

type transitionDocument struct {
	Date         string `xml:"Date,omitempty"`
	Days         *int32 `xml:"Days,omitempty"`
	StorageClass string `xml:"StorageClass,omitempty"`
}

type noncurrentTransitionDocument struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty"`
	StorageClass            string `xml:"StorageClass,omitempty"`
}

type noncurrentExpirationDocument struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty"`
}

type abortIncompleteUploadDocument struct {
	DaysAfterInitiation *int32 `xml:"DaysAfterInitiation,omitempty"`
}

func newLifecycleConfigurationDocument(rules []types.LifecycleRule) lifecycleConfigurationDocument {
	doc := lifecycleConfigurationDocument{XMLNS: s3Namespace, Rules: make([]lifecycleRuleDocument, 0, len(rules))}
	for _, rule := range rules {
		converted := lifecycleRuleDocument{
			ID:     aws.ToString(rule.ID),
			Status: string(rule.Status),
			Prefix: aws.ToString(rule.Prefix),
		}
		if f := rule.Filter; f != nil {
			filter := &lifecycleFilterDocument{
				Prefix:                aws.ToString(f.Prefix),
				ObjectSizeGreaterThan: f.ObjectSizeGreaterThan,
				ObjectSizeLessThan:    f.ObjectSizeLessThan,
			}
			if f.Tag != nil {
				filter.Tag = &tagDocument{Key: aws.ToString(f.Tag.Key), Value: aws.ToString(f.Tag.Value)}
			}
			if f.And != nil {
				filter.And = &lifecycleAndDocument{
					Prefix:                aws.ToString(f.And.Prefix),
					Tags:                  newTagDocuments(f.And.Tags),
					ObjectSizeGreaterThan: f.And.ObjectSizeGreaterThan,
					ObjectSizeLessThan:    f.And.ObjectSizeLessThan,
				}
			}
			converted.Filter = filter
		}
		if e := rule.Expiration; e != nil {
			converted.Expiration = &lifecycleExpirationDocument{
				Date:                      formatDate(e.Date),
				Days:                      e.Days,
				ExpiredObjectDeleteMarker: e.ExpiredObjectDeleteMarker,
			}
		}
		for _, t := range rule.Transitions {
			converted.Transitions = append(converted.Transitions, transitionDocument{
				Date: formatDate(t.Date), Days: t.Days, StorageClass: string(t.StorageClass),
			})
		}
		for _, t := range rule.NoncurrentVersionTransitions {
			converted.NoncurrentVersionTransitions = append(converted.NoncurrentVersionTransitions,
				noncurrentTransitionDocument{
					NoncurrentDays:          t.NoncurrentDays,
					NewerNoncurrentVersions: t.NewerNoncurrentVersions,
					StorageClass:            string(t.StorageClass),
				})
		}
		if e := rule.NoncurrentVersionExpiration; e != nil {
			converted.NoncurrentVersionExpiration = &noncurrentExpirationDocument{
				NoncurrentDays:          e.NoncurrentDays,
				NewerNoncurrentVersions: e.NewerNoncurrentVersions,
			}
		}
		if a := rule.AbortIncompleteMultipartUpload; a != nil {
			converted.AbortIncompleteMultipartUpload = &abortIncompleteUploadDocument{
				DaysAfterInitiation: a.DaysAfterInitiation,
			}
		}
		doc.Rules = append(doc.Rules, converted)
	}
	return doc
}

// ---------------------------------------------------------------------------
// ?notification
// ---------------------------------------------------------------------------

type notificationConfigurationDocument struct {
	XMLName                    xml.Name                    `xml:"NotificationConfiguration"`
	XMLNS                      string                      `xml:"xmlns,attr,omitempty"`
	TopicConfigurations        []topicConfigurationPD      `xml:"TopicConfiguration,omitempty"`
	QueueConfigurations        []queueConfigurationPD      `xml:"QueueConfiguration,omitempty"`
	CloudFunctionConfiguration []cloudFunctionConfigPD     `xml:"CloudFunctionConfiguration,omitempty"`
	EventBridgeConfiguration   *eventBridgeConfigurationPD `xml:"EventBridgeConfiguration,omitempty"`
}

type topicConfigurationPD struct {
	ID     string                `xml:"Id,omitempty"`
	Topic  string                `xml:"Topic,omitempty"`
	Events []string              `xml:"Event"`
	Filter *notificationFilterPD `xml:"Filter,omitempty"`
}

type queueConfigurationPD struct {
	ID     string                `xml:"Id,omitempty"`
	Queue  string                `xml:"Queue,omitempty"`
	Events []string              `xml:"Event"`
	Filter *notificationFilterPD `xml:"Filter,omitempty"`
}

type cloudFunctionConfigPD struct {
	ID            string                `xml:"Id,omitempty"`
	CloudFunction string                `xml:"CloudFunction,omitempty"`
	Events        []string              `xml:"Event"`
	Filter        *notificationFilterPD `xml:"Filter,omitempty"`
}

type eventBridgeConfigurationPD struct{}

type notificationFilterPD struct {
	S3Key *s3KeyFilterPD `xml:"S3Key,omitempty"`
}

type s3KeyFilterPD struct {
	FilterRules []filterRulePD `xml:"FilterRule"`
}

type filterRulePD struct {
	Name  string `xml:"Name,omitempty"`
	Value string `xml:"Value,omitempty"`
}

func newNotificationFilter(filter *types.NotificationConfigurationFilter) *notificationFilterPD {
	if filter == nil || filter.Key == nil {
		return nil
	}
	rules := make([]filterRulePD, 0, len(filter.Key.FilterRules))
	for _, rule := range filter.Key.FilterRules {
		rules = append(rules, filterRulePD{Name: string(rule.Name), Value: aws.ToString(rule.Value)})
	}
	return &notificationFilterPD{S3Key: &s3KeyFilterPD{FilterRules: rules}}
}

func newNotificationConfigurationDocument(
	output *s3.GetBucketNotificationConfigurationOutput,
) notificationConfigurationDocument {
	doc := notificationConfigurationDocument{XMLNS: s3Namespace}
	for _, topic := range output.TopicConfigurations {
		doc.TopicConfigurations = append(doc.TopicConfigurations, topicConfigurationPD{
			ID:     aws.ToString(topic.Id),
			Topic:  aws.ToString(topic.TopicArn),
			Events: eventStrings(topic.Events),
			Filter: newNotificationFilter(topic.Filter),
		})
	}
	for _, queue := range output.QueueConfigurations {
		doc.QueueConfigurations = append(doc.QueueConfigurations, queueConfigurationPD{
			ID:     aws.ToString(queue.Id),
			Queue:  aws.ToString(queue.QueueArn),
			Events: eventStrings(queue.Events),
			Filter: newNotificationFilter(queue.Filter),
		})
	}
	for _, lambda := range output.LambdaFunctionConfigurations {
		doc.CloudFunctionConfiguration = append(doc.CloudFunctionConfiguration, cloudFunctionConfigPD{
			ID:            aws.ToString(lambda.Id),
			CloudFunction: aws.ToString(lambda.LambdaFunctionArn),
			Events:        eventStrings(lambda.Events),
			Filter:        newNotificationFilter(lambda.Filter),
		})
	}
	if output.EventBridgeConfiguration != nil {
		doc.EventBridgeConfiguration = &eventBridgeConfigurationPD{}
	}
	return doc
}

func eventStrings(events []types.Event) []string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		names = append(names, string(event))
	}
	return names
}

// ---------------------------------------------------------------------------
// ?replication
// ---------------------------------------------------------------------------

type replicationConfigurationDocument struct {
	XMLName xml.Name                  `xml:"ReplicationConfiguration"`
	XMLNS   string                    `xml:"xmlns,attr,omitempty"`
	Role    string                    `xml:"Role,omitempty"`
	Rules   []replicationRuleDocument `xml:"Rule"`
}

type replicationRuleDocument struct {
	ID                        string                     `xml:"ID,omitempty"`
	Priority                  *int32                     `xml:"Priority,omitempty"`
	Prefix                    string                     `xml:"Prefix,omitempty"`
	Status                    string                     `xml:"Status,omitempty"`
	Filter                    *replicationFilterDocument `xml:"Filter,omitempty"`
	SourceSelectionCriteria   *sourceSelectionPD         `xml:"SourceSelectionCriteria,omitempty"`
	ExistingObjectReplication *statusOnlyPD              `xml:"ExistingObjectReplication,omitempty"`
	DeleteMarkerReplication   *statusOnlyPD              `xml:"DeleteMarkerReplication,omitempty"`
	Destination               *replicationDestinationPD  `xml:"Destination,omitempty"`
}

type replicationFilterDocument struct {
	Prefix string            `xml:"Prefix,omitempty"`
	Tag    *tagDocument      `xml:"Tag,omitempty"`
	And    *replicationAndPD `xml:"And,omitempty"`
}

type replicationAndPD struct {
	Prefix string        `xml:"Prefix,omitempty"`
	Tags   []tagDocument `xml:"Tag,omitempty"`
}

type statusOnlyPD struct {
	Status string `xml:"Status,omitempty"`
}

type sourceSelectionPD struct {
	SseKmsEncryptedObjects *statusOnlyPD `xml:"SseKmsEncryptedObjects,omitempty"`
	ReplicaModifications   *statusOnlyPD `xml:"ReplicaModifications,omitempty"`
}

type replicationDestinationPD struct {
	Bucket                   string                `xml:"Bucket,omitempty"`
	Account                  string                `xml:"Account,omitempty"`
	StorageClass             string                `xml:"StorageClass,omitempty"`
	AccessControlTranslation *accessControlXlatePD `xml:"AccessControlTranslation,omitempty"`
	EncryptionConfiguration  *encryptionConfigPD   `xml:"EncryptionConfiguration,omitempty"`
	ReplicationTime          *replicationTimePD    `xml:"ReplicationTime,omitempty"`
	Metrics                  *replicationMetricsPD `xml:"Metrics,omitempty"`
}

type accessControlXlatePD struct {
	Owner string `xml:"Owner,omitempty"`
}

type encryptionConfigPD struct {
	ReplicaKmsKeyID string `xml:"ReplicaKmsKeyID,omitempty"`
}

type replicationTimePD struct {
	Status string             `xml:"Status,omitempty"`
	Time   *minutesDocumentPD `xml:"Time,omitempty"`
}

type replicationMetricsPD struct {
	Status         string             `xml:"Status,omitempty"`
	EventThreshold *minutesDocumentPD `xml:"EventThreshold,omitempty"`
}

type minutesDocumentPD struct {
	Minutes *int32 `xml:"Minutes,omitempty"`
}

func newReplicationConfigurationDocument(config *types.ReplicationConfiguration) replicationConfigurationDocument {
	doc := replicationConfigurationDocument{XMLNS: s3Namespace}
	if config == nil {
		return doc
	}
	doc.Role = aws.ToString(config.Role)
	doc.Rules = make([]replicationRuleDocument, 0, len(config.Rules))
	for _, rule := range config.Rules {
		converted := replicationRuleDocument{
			ID:       aws.ToString(rule.ID),
			Priority: rule.Priority,
			Prefix:   aws.ToString(rule.Prefix),
			Status:   string(rule.Status),
		}
		if f := rule.Filter; f != nil {
			filter := &replicationFilterDocument{Prefix: aws.ToString(f.Prefix)}
			if f.Tag != nil {
				filter.Tag = &tagDocument{Key: aws.ToString(f.Tag.Key), Value: aws.ToString(f.Tag.Value)}
			}
			if f.And != nil {
				filter.And = &replicationAndPD{
					Prefix: aws.ToString(f.And.Prefix),
					Tags:   newTagDocuments(f.And.Tags),
				}
			}
			converted.Filter = filter
		}
		if s := rule.SourceSelectionCriteria; s != nil {
			criteria := &sourceSelectionPD{}
			if s.SseKmsEncryptedObjects != nil {
				criteria.SseKmsEncryptedObjects = &statusOnlyPD{Status: string(s.SseKmsEncryptedObjects.Status)}
			}
			if s.ReplicaModifications != nil {
				criteria.ReplicaModifications = &statusOnlyPD{Status: string(s.ReplicaModifications.Status)}
			}
			converted.SourceSelectionCriteria = criteria
		}
		if e := rule.ExistingObjectReplication; e != nil {
			converted.ExistingObjectReplication = &statusOnlyPD{Status: string(e.Status)}
		}
		if d := rule.DeleteMarkerReplication; d != nil {
			converted.DeleteMarkerReplication = &statusOnlyPD{Status: string(d.Status)}
		}
		if d := rule.Destination; d != nil {
			destination := &replicationDestinationPD{
				Bucket:       aws.ToString(d.Bucket),
				Account:      aws.ToString(d.Account),
				StorageClass: string(d.StorageClass),
			}
			if d.AccessControlTranslation != nil {
				destination.AccessControlTranslation = &accessControlXlatePD{
					Owner: string(d.AccessControlTranslation.Owner),
				}
			}
			if d.EncryptionConfiguration != nil {
				destination.EncryptionConfiguration = &encryptionConfigPD{
					ReplicaKmsKeyID: aws.ToString(d.EncryptionConfiguration.ReplicaKmsKeyID),
				}
			}
			if d.ReplicationTime != nil {
				destination.ReplicationTime = &replicationTimePD{Status: string(d.ReplicationTime.Status)}
				if d.ReplicationTime.Time != nil {
					destination.ReplicationTime.Time = &minutesDocumentPD{Minutes: d.ReplicationTime.Time.Minutes}
				}
			}
			if d.Metrics != nil {
				destination.Metrics = &replicationMetricsPD{Status: string(d.Metrics.Status)}
				if d.Metrics.EventThreshold != nil {
					destination.Metrics.EventThreshold = &minutesDocumentPD{Minutes: d.Metrics.EventThreshold.Minutes}
				}
			}
			converted.Destination = destination
		}
		doc.Rules = append(doc.Rules, converted)
	}
	return doc
}

// ---------------------------------------------------------------------------
// ?website
// ---------------------------------------------------------------------------

type websiteConfigurationDocument struct {
	XMLName               xml.Name               `xml:"WebsiteConfiguration"`
	XMLNS                 string                 `xml:"xmlns,attr,omitempty"`
	RedirectAllRequestsTo *redirectAllRequestsPD `xml:"RedirectAllRequestsTo,omitempty"`
	IndexDocument         *indexDocumentPD       `xml:"IndexDocument,omitempty"`
	ErrorDocument         *errorDocumentPD       `xml:"ErrorDocument,omitempty"`
	RoutingRules          *routingRulesPD        `xml:"RoutingRules,omitempty"`
}

type redirectAllRequestsPD struct {
	HostName string `xml:"HostName,omitempty"`
	Protocol string `xml:"Protocol,omitempty"`
}

type indexDocumentPD struct {
	Suffix string `xml:"Suffix,omitempty"`
}

type errorDocumentPD struct {
	Key string `xml:"Key,omitempty"`
}

type routingRulesPD struct {
	Rules []routingRulePD `xml:"RoutingRule"`
}

type routingRulePD struct {
	Condition *routingConditionPD `xml:"Condition,omitempty"`
	Redirect  *routingRedirectPD  `xml:"Redirect,omitempty"`
}

type routingConditionPD struct {
	HTTPErrorCodeReturnedEquals string `xml:"HttpErrorCodeReturnedEquals,omitempty"`
	KeyPrefixEquals             string `xml:"KeyPrefixEquals,omitempty"`
}

type routingRedirectPD struct {
	HostName             string `xml:"HostName,omitempty"`
	HTTPRedirectCode     string `xml:"HttpRedirectCode,omitempty"`
	Protocol             string `xml:"Protocol,omitempty"`
	ReplaceKeyPrefixWith string `xml:"ReplaceKeyPrefixWith,omitempty"`
	ReplaceKeyWith       string `xml:"ReplaceKeyWith,omitempty"`
}

func newWebsiteConfigurationDocument(output *s3.GetBucketWebsiteOutput) websiteConfigurationDocument {
	doc := websiteConfigurationDocument{XMLNS: s3Namespace}
	if r := output.RedirectAllRequestsTo; r != nil {
		doc.RedirectAllRequestsTo = &redirectAllRequestsPD{
			HostName: aws.ToString(r.HostName), Protocol: string(r.Protocol),
		}
	}
	if i := output.IndexDocument; i != nil {
		doc.IndexDocument = &indexDocumentPD{Suffix: aws.ToString(i.Suffix)}
	}
	if e := output.ErrorDocument; e != nil {
		doc.ErrorDocument = &errorDocumentPD{Key: aws.ToString(e.Key)}
	}
	if len(output.RoutingRules) > 0 {
		rules := &routingRulesPD{Rules: make([]routingRulePD, 0, len(output.RoutingRules))}
		for _, rule := range output.RoutingRules {
			converted := routingRulePD{}
			if c := rule.Condition; c != nil {
				converted.Condition = &routingConditionPD{
					HTTPErrorCodeReturnedEquals: aws.ToString(c.HttpErrorCodeReturnedEquals),
					KeyPrefixEquals:             aws.ToString(c.KeyPrefixEquals),
				}
			}
			if r := rule.Redirect; r != nil {
				converted.Redirect = &routingRedirectPD{
					HostName:             aws.ToString(r.HostName),
					HTTPRedirectCode:     aws.ToString(r.HttpRedirectCode),
					Protocol:             string(r.Protocol),
					ReplaceKeyPrefixWith: aws.ToString(r.ReplaceKeyPrefixWith),
					ReplaceKeyWith:       aws.ToString(r.ReplaceKeyWith),
				}
			}
			rules.Rules = append(rules.Rules, converted)
		}
		doc.RoutingRules = rules
	}
	return doc
}

// bucketLoggingStatus converts a parsed ?logging document into the SDK type the
// backend call takes. A document with no <LoggingEnabled> disables logging.
func (d bucketLoggingStatusDocument) bucketLoggingStatus() *types.BucketLoggingStatus {
	status := &types.BucketLoggingStatus{}
	if d.LoggingEnabled == nil {
		return status
	}

	enabled := &types.LoggingEnabled{
		TargetBucket: aws.String(d.LoggingEnabled.TargetBucket),
		TargetPrefix: aws.String(d.LoggingEnabled.TargetPrefix),
	}
	if d.LoggingEnabled.TargetGrants != nil {
		grants := make([]types.TargetGrant, 0, len(d.LoggingEnabled.TargetGrants.Grants))
		for _, grant := range d.LoggingEnabled.TargetGrants.Grants {
			converted := types.TargetGrant{Permission: types.BucketLogsPermission(grant.Permission)}
			if grant.Grantee != nil {
				converted.Grantee = &types.Grantee{
					Type:         types.Type(grant.Grantee.granteeType()),
					ID:           aws.String(grant.Grantee.ID),
					DisplayName:  aws.String(grant.Grantee.DisplayName),
					EmailAddress: aws.String(grant.Grantee.EmailAddress),
					URI:          aws.String(grant.Grantee.URI),
				}
			}
			grants = append(grants, converted)
		}
		enabled.TargetGrants = grants
	}
	status.LoggingEnabled = enabled
	return status
}
