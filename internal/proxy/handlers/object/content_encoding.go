package object

import "strings"

// StripAWSChunked removes the aws-chunked token from a Content-Encoding value.
//
// aws-chunked describes the transfer framing of the request body, not the
// stored representation. The proxy decodes that framing before encrypting, so
// storing the header verbatim would tell every later reader that the object is
// aws-chunked encoded when it is not. Real S3 removes the token for the same
// reason. Any other encoding the client listed (gzip, for instance) is genuine
// and is preserved.
//
// Returns the empty string when nothing but aws-chunked was listed, so the
// caller can leave Content-Encoding unset.
func StripAWSChunked(contentEncoding string) string {
	if contentEncoding == "" {
		return ""
	}
	parts := strings.Split(contentEncoding, ",")
	kept := parts[:0]
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || strings.EqualFold(trimmed, "aws-chunked") {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, ", ")
}
