//go:build e2e

package harness

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Result is one run of a client binary. Stdout is kept apart from Stderr
// because a client's machine-readable output (rclone lsjson, s3cmd ls) goes to
// one and its verdict to the other; Combined is what a failure message quotes,
// and what the verdict table records as "the client's words".
type Result struct {
	Bin      string
	Args     []string
	Stdout   string
	Stderr   string
	Combined string
	ExitCode int
}

// Command is the printable form of the invocation, for a failure message.
func (r Result) Command() string {
	return r.Bin + " " + strings.Join(r.Args, " ")
}

// OK reports whether the client considered the run a success.
func (r Result) OK() bool { return r.ExitCode == 0 }

// Run executes a client binary and returns what it said. It never fails the
// test: for these suites a non-zero exit is frequently the finding, so the
// caller decides what the exit code means.
func Run(ctx context.Context, bin string, args ...string) Result {
	return RunWithEnv(ctx, nil, bin, args...)
}

// RunWithEnv is Run with extra KEY=VALUE entries appended to the environment.
func RunWithEnv(ctx context.Context, extraEnv []string, bin string, args ...string) Result {
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 - test harness, arguments are built in-tree
	cmd.Env = append(os.Environ(), extraEnv...)

	var stdout, stderr, combined bytes.Buffer
	cmd.Stdout = io2(&stdout, &combined)
	cmd.Stderr = io2(&stderr, &combined)

	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			// The binary could not be started at all — a missing install, a
			// cancelled context. Report it in the output rather than as an exit
			// code the client never produced.
			code = -1
			combined.WriteString("\nharness: " + err.Error())
			stderr.WriteString("\nharness: " + err.Error())
		}
	}

	return Result{
		Bin:      bin,
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Combined: combined.String(),
		ExitCode: code,
	}
}

// MustRun is Run with the assertion that the client succeeded. Used for the
// steps that set a case up, never for the step a case is about.
func MustRun(t *testing.T, ctx context.Context, bin string, args ...string) Result {
	t.Helper()
	r := Run(ctx, bin, args...)
	require.Truef(t, r.OK(), "%s exited %d:\n%s", r.Command(), r.ExitCode, r.Combined)
	return r
}

// io2 writes to both sinks, so Combined keeps the interleaving the client
// produced while each stream stays separately parseable.
func io2(a, b *bytes.Buffer) *teeBuffer { return &teeBuffer{a: a, b: b} }

type teeBuffer struct{ a, b *bytes.Buffer }

func (t *teeBuffer) Write(p []byte) (int, error) {
	t.a.Write(p)
	t.b.Write(p)
	return len(p), nil
}

// FirstMatch returns the first line of out matching re, trimmed. Used to lift a
// client's verdict out of its log so the verdict table quotes the client rather
// than the suite's paraphrase.
func FirstMatch(out string, re *regexp.Regexp) string {
	for _, line := range strings.Split(out, "\n") {
		if re.MatchString(line) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// Redact replaces every occurrence of the scratch directory with a placeholder.
// A client prints absolute source paths in its errors, and a verdict table that
// carries a build agent's temporary directory is unreadable and unstable.
func Redact(out, dir string) string {
	if dir == "" {
		return out
	}
	return strings.ReplaceAll(out, dir, "<work>")
}
