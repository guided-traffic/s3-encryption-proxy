package etag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A content MD5 in hex is the one shape that is marked, because it is the one
// shape a client reads as a promise (ADR 0032 D2).
func TestEtagMarkOnlyTouchesTheDigestShape(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"a quoted content MD5":       {`"2c52a8e3b689c5ea7f55444e2000b35a"`, `"2c52a8e3b689c5ea7f55444e2000b35a-0"`},
		"a bare content MD5":         {"2c52a8e3b689c5ea7f55444e2000b35a", "2c52a8e3b689c5ea7f55444e2000b35a-0"},
		"upper case hex is a digest": {`"2C52A8E3B689C5EA7F55444E2000B35A"`, `"2C52A8E3B689C5EA7F55444E2000B35A-0"`},

		// Everything below already says it is not a content digest, or cannot be
		// mistaken for one.
		"a multipart tag":          {`"2c52a8e3b689c5ea7f55444e2000b35a-3"`, `"2c52a8e3b689c5ea7f55444e2000b35a-3"`},
		"a single-part multipart":  {`"2c52a8e3b689c5ea7f55444e2000b35a-1"`, `"2c52a8e3b689c5ea7f55444e2000b35a-1"`},
		"already marked":           {`"2c52a8e3b689c5ea7f55444e2000b35a-0"`, `"2c52a8e3b689c5ea7f55444e2000b35a-0"`},
		"the proxy's held part":    {`"9ae471bc-2097152"`, `"9ae471bc-2097152"`},
		"a zero-length held part":  {`"00000000-0"`, `"00000000-0"`},
		"31 hex digits":            {`"2c52a8e3b689c5ea7f55444e2000b35"`, `"2c52a8e3b689c5ea7f55444e2000b35"`},
		"33 hex digits":            {`"2c52a8e3b689c5ea7f55444e2000b35ab"`, `"2c52a8e3b689c5ea7f55444e2000b35ab"`},
		"32 characters, not hex":   {`"2c52a8e3b689c5ea7f55444e2000b35z"`, `"2c52a8e3b689c5ea7f55444e2000b35z"`},
		"empty":                    {"", ""},
		"empty quoted":             {`""`, `""`},
		"a weak tag is left alone": {`W/"2c52a8e3b689c5ea7f55444e2000b35a"`, `W/"2c52a8e3b689c5ea7f55444e2000b35a"`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, Mark(tc.in))
		})
	}
}

// Unmark is the exact inverse, and it is driven by shape: a tag that ends in -0
// without a content MD5 in front of it is a tag this proxy answers itself, and
// trimming it would corrupt it (ADR 0032 D5).
func TestEtagUnmarkIsShapeDrivenNotATrim(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"a marked tag":            {`"2c52a8e3b689c5ea7f55444e2000b35a-0"`, `"2c52a8e3b689c5ea7f55444e2000b35a"`},
		"a bare marked tag":       {"2c52a8e3b689c5ea7f55444e2000b35a-0", "2c52a8e3b689c5ea7f55444e2000b35a"},
		"a zero-length held part": {`"00000000-0"`, `"00000000-0"`},
		"a held part":             {`"9ae471bc-2097152"`, `"9ae471bc-2097152"`},
		"an unmarked digest":      {`"2c52a8e3b689c5ea7f55444e2000b35a"`, `"2c52a8e3b689c5ea7f55444e2000b35a"`},
		"a multipart tag":         {`"2c52a8e3b689c5ea7f55444e2000b35a-3"`, `"2c52a8e3b689c5ea7f55444e2000b35a-3"`},
		"only the marker":         {`"-0"`, `"-0"`},
		"empty":                   {"", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, Unmark(tc.in))
		})
	}
}

// What the proxy answers, a client sends back. That round trip is the whole of
// D4: anything else makes a conditional request fail against an object that did
// not change.
func TestEtagRoundTripsForEveryShapeTheProxyAnswers(t *testing.T) {
	for _, answered := range []string{
		`"2c52a8e3b689c5ea7f55444e2000b35a"`,
		`"2c52a8e3b689c5ea7f55444e2000b35a-3"`,
		`"9ae471bc-2097152"`,
		`"00000000-0"`,
		`"00000000-0"`,
	} {
		t.Run(answered, func(t *testing.T) {
			require.Equal(t, answered, Unmark(Mark(answered)),
				"a client that returns what it was given must revalidate")
		})
	}
}

// Both precondition headers may carry a list, and both may carry "*", which is
// not a tag at all.
func TestEtagUnmarkListHandlesEveryHeaderForm(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"a single marked tag": {
			`"2c52a8e3b689c5ea7f55444e2000b35a-0"`,
			`"2c52a8e3b689c5ea7f55444e2000b35a"`,
		},
		"a list, spaces preserved": {
			`"2c52a8e3b689c5ea7f55444e2000b35a-0", "58d6a6131ee4337c8877716b2af05a6d-0"`,
			`"2c52a8e3b689c5ea7f55444e2000b35a", "58d6a6131ee4337c8877716b2af05a6d"`,
		},
		"a mixed list": {
			`"2c52a8e3b689c5ea7f55444e2000b35a-0", "58d6a6131ee4337c8877716b2af05a6d-3"`,
			`"2c52a8e3b689c5ea7f55444e2000b35a", "58d6a6131ee4337c8877716b2af05a6d-3"`,
		},
		"the wildcard":              {"*", "*"},
		"empty":                     {"", ""},
		"an unmarked tag":           {`"2c52a8e3b689c5ea7f55444e2000b35a"`, `"2c52a8e3b689c5ea7f55444e2000b35a"`},
		"a list carrying no marker": {`"abc", "def"`, `"abc", "def"`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, UnmarkList(tc.in))
		})
	}
}

// S3 cannot answer -0: a completed multipart upload has at least one part. That
// is the premise the marker rests on, and -1 is what it rules out.
func TestEtagTheMarkerIsNotAShapeS3Produces(t *testing.T) {
	const native = `"2c52a8e3b689c5ea7f55444e2000b35a-1"`

	assert.Equal(t, native, Mark(native), "a one-part multipart object is native S3 and is not marked")
	assert.Equal(t, native, Unmark(native), "and it is never mistaken for a marked tag")
}
