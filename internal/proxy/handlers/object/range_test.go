package object

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseByteRange(t *testing.T) {
	const total = 1000

	cases := []struct {
		name      string
		header    string
		wantStart int64
		wantLen   int64
		wantCR    string
	}{
		{"explicit_window", "bytes=0-99", 0, 100, "bytes 0-99/1000"},
		{"mid_object", "bytes=100-199", 100, 100, "bytes 100-199/1000"},
		{"open_ended", "bytes=900-", 900, 100, "bytes 900-999/1000"},
		{"whole_object", "bytes=0-999", 0, 1000, "bytes 0-999/1000"},
		{"end_beyond_object_is_clamped", "bytes=990-5000", 990, 10, "bytes 990-999/1000"},
		{"suffix", "bytes=-100", 900, 100, "bytes 900-999/1000"},
		{"suffix_larger_than_object", "bytes=-5000", 0, 1000, "bytes 0-999/1000"},
		{"single_byte", "bytes=42-42", 42, 1, "bytes 42-42/1000"},
		{"last_byte", "bytes=999-999", 999, 1, "bytes 999-999/1000"},
		// kopia reads its pack blobs like this.
		{"small_read_at_offset", "bytes=32-63", 32, 32, "bytes 32-63/1000"},
		{"whitespace_tolerated", " bytes=10-19 ", 10, 10, "bytes 10-19/1000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br, err := parseByteRange(tc.header, total)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStart, br.start, "start")
			assert.Equal(t, tc.wantLen, br.length, "length")
			assert.Equal(t, tc.wantCR, br.contentRange())
		})
	}
}

func TestParseByteRange_Errors(t *testing.T) {
	const total = 1000

	cases := map[string]struct {
		header string
		want   error
	}{
		"start_past_end":     {"bytes=1000-1099", errUnsatisfiableRange},
		"start_far_past_end": {"bytes=999999-", errUnsatisfiableRange},
		"zero_suffix":        {"bytes=-0", errUnsatisfiableRange},
		"multiple_ranges":    {"bytes=0-9,20-29", errMultipleRanges},
		"missing_unit":       {"0-99", errMalformedRange},
		"wrong_unit":         {"items=0-99", errMalformedRange},
		"no_dash":            {"bytes=100", errMalformedRange},
		"end_before_start":   {"bytes=100-50", errMalformedRange},
		"negative_start":     {"bytes=-100-200", errMalformedRange},
		"empty_spec":         {"bytes=-", errMalformedRange},
		"not_a_number":       {"bytes=abc-def", errMalformedRange},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseByteRange(tc.header, total)
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, tc.want), "got %v, want %v", err, tc.want)
		})
	}
}

// A zero-length object can satisfy no range at all.
func TestParseByteRange_EmptyObject(t *testing.T) {
	_, err := parseByteRange("bytes=0-", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errUnsatisfiableRange))
}

func TestContentRangeStart(t *testing.T) {
	cases := map[string]int64{
		"bytes 0-99/1000":                0,
		"bytes 100-199/1000":             100,
		"bytes 900-999/1000":             900,
		" bytes 42-42/43 ":               42,
		"bytes 0-0/1":                    0,
		"bytes 1048576-2097151/10485760": 1048576,
	}
	for header, want := range cases {
		t.Run(header, func(t *testing.T) {
			got, err := contentRangeStart(header)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestContentRangeStart_Errors(t *testing.T) {
	for _, header := range []string{"", "0-99/1000", "bytes 0-99", "bytes abc-99/1000", "items 0-99/1000"} {
		t.Run(header, func(t *testing.T) {
			_, err := contentRangeStart(header)
			require.Error(t, err)
		})
	}
}
