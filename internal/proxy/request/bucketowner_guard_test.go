package request

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerlessInputs are the two SDK input types that carry no ExpectedBucketOwner
// field, because S3 defines none for them: CreateBucket asserts the owner of a
// bucket that does not exist yet, and ListBuckets is account-scoped rather than
// bucket-scoped.
var ownerlessInputs = map[string]string{
	"CreateBucketInput": "the bucket does not exist yet, so it has no owner to assert",
	"ListBucketsInput":  "account-scoped, not bucket-scoped",
}

// TestEveryBackendCallCarriesTheOwnerGuard walks the handler sources and fails
// when an s3.XxxInput literal does not set ExpectedBucketOwner.
//
// The guard is only worth what its weakest verb honours (ADR 0007 D14), and the
// way it decays is a new backend call that simply forgets the field — which
// compiles, passes every test of its own behaviour, and silently fails open. A
// per-verb test cannot catch a verb nobody wrote a test for, so this reads the
// source instead.
//
// It requires the field to be set inside the composite literal rather than
// assigned afterwards. That is the convention across all three handler packages
// and it is what makes the call site readable at a glance.
func TestEveryBackendCallCarriesTheOwnerGuard(t *testing.T) {
	root, err := filepath.Abs("../handlers")
	require.NoError(t, err)

	type site struct {
		file string
		line int
		typ  string
	}
	var missing []site
	seen := 0

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "s3" || !strings.HasSuffix(sel.Sel.Name, "Input") {
				return true
			}
			if _, exempt := ownerlessInputs[sel.Sel.Name]; exempt {
				return true
			}

			seen++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ExpectedBucketOwner" {
					return true
				}
			}

			rel, _ := filepath.Rel(root, path)
			missing = append(missing, site{
				file: rel,
				line: fset.Position(lit.Pos()).Line,
				typ:  sel.Sel.Name,
			})
			return true
		})
		return nil
	})
	require.NoError(t, walkErr)

	// A guard that silently stopped finding call sites is no guard. The count is
	// a floor, not a fixture: it does not need updating when a verb is added.
	assert.Greater(t, seen, 50, "the walk should find every backend call the handlers make")

	for _, m := range missing {
		t.Errorf("%s:%d: s3.%s does not set ExpectedBucketOwner — "+
			"every backend call carries the client's ownership precondition (ADR 0007 D14). "+
			"Set it in the literal: ExpectedBucketOwner: request.ExpectedBucketOwner(r)",
			m.file, m.line, m.typ)
	}
}
