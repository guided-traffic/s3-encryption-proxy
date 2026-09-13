// Package etag marks and unmarks the entity tags this proxy answers.
//
// An entity tag is a change token, never a digest of the object's content
// (ADR 0032 D1). The backend's tag for an encrypted object is the MD5 of the
// stored bytes: thirty-two hex digits, which is exactly the shape S3 gives the
// content MD5 of an unencrypted single-part object. Clients read that shape as a
// promise and act on it - one deletes the object it just uploaded when the
// comparison fails, another refuses to upload at all.
//
// Mark corrects the shape without touching the value: a thirty-two-hex tag is
// answered with the suffix -0, which stays inside the <hex>-<number> grammar
// every S3 client already parses and which S3 itself cannot produce, since a
// completed multipart upload has at least one part. Unmark is its exact inverse
// and runs on every tag a client sends back, so a client that returns what it
// was given revalidates as if the marker were not there.
package etag

import "strings"

// marker is the suffix that says "this is not a content digest".
const marker = "-0"

// digestLen is the length of a content MD5 in hex, and the only shape that is
// marked.
const digestLen = 32

// Mark answers value with the marker when value carries the shape of a content
// MD5. Any other shape is returned unchanged, a multipart <hex>-N included.
// Surrounding quotes are preserved, because that is how an entity tag travels.
func Mark(value string) string {
	inner, quoted := unquote(value)
	if !isHexDigest(inner) {
		return value
	}
	return requote(inner+marker, quoted)
}

// Unmark is the exact inverse of Mark.
//
// The rule is driven by shape, never by trimming a trailing -0: this proxy
// answers entity tags of its own that legitimately end in -0 - a held part of
// length zero is one - and a trim rule would corrupt them (ADR 0032 D5). A tag
// is unmarked only when removing the suffix leaves a content-MD5 shape.
func Unmark(value string) string {
	inner, quoted := unquote(value)
	head, found := strings.CutSuffix(inner, marker)
	if !found || !isHexDigest(head) {
		return value
	}
	return requote(head, quoted)
}

// UnmarkList unmarks every tag in an If-Match or If-None-Match header. Both may
// carry a comma-separated list, and both may carry "*", which is not a tag and
// passes through untouched.
func UnmarkList(header string) string {
	if header == "" || !strings.Contains(header, marker) {
		return header
	}
	tags := strings.Split(header, ",")
	for i, tag := range tags {
		lead := leadingSpace(tag)
		tags[i] = lead + Unmark(strings.TrimSpace(tag))
	}
	return strings.Join(tags, ",")
}

// isHexDigest reports whether s is exactly a content MD5 in hex. Written out
// rather than compiled as a regular expression: it runs on every entity tag the
// proxy answers and on every precondition header it reads.
func isHexDigest(s string) bool {
	if len(s) != digestLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func unquote(value string) (inner string, quoted bool) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1], true
	}
	return value, false
}

func requote(inner string, quoted bool) string {
	if quoted {
		return `"` + inner + `"`
	}
	return inner
}

func leadingSpace(tag string) string {
	for i := 0; i < len(tag); i++ {
		if tag[i] != ' ' && tag[i] != '\t' {
			return tag[:i]
		}
	}
	return tag
}
