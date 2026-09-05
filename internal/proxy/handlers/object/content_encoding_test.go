package object

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// aws-chunked describes the request framing, which the proxy decodes before
// encrypting. Storing it on the object tells every later reader the stored bytes
// are aws-chunked encoded, which they are not. Real S3 strips it too.
func TestStripAWSChunked(t *testing.T) {
	cases := map[string]string{
		"":                        "",
		"aws-chunked":             "",
		"AWS-CHUNKED":             "",
		"  aws-chunked  ":         "",
		"gzip":                    "gzip",
		"gzip, aws-chunked":       "gzip",
		"aws-chunked, gzip":       "gzip",
		"gzip,aws-chunked":        "gzip",
		"gzip, aws-chunked, br":   "gzip, br",
		"aws-chunked,aws-chunked": "",
		"identity":                "identity",
		"gzip, identity":          "gzip, identity",
		",":                       "",
	}

	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, StripAWSChunked(in))
		})
	}
}
