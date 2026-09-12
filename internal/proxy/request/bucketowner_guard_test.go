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
//
// And it checks the VALUE, not only the key: a field present is not a guard —
// "ExpectedBucketOwner: nil" satisfies a walk that looks for the name alone and
// fails open on every request. The value has to come from the client's header,
// either as the call or through a local the same file assigns from it (the
// multipart producer reads it once and hands it to every worker).
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

		// Locals assigned from the header reader in this file, so a call site
		// that hoists the value out of a loop is still recognised.
		ownerLocals := map[string]bool{}
		ast.Inspect(parsed, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assign.Rhs {
				if !isOwnerHeaderCall(rhs) || i >= len(assign.Lhs) {
					continue
				}
				if name, ok := assign.Lhs[i].(*ast.Ident); ok {
					ownerLocals[name.Name] = true
				}
			}
			return true
		})

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
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "ExpectedBucketOwner" {
					continue
				}
				if isOwnerHeaderCall(kv.Value) {
					return true
				}
				if name, ok := kv.Value.(*ast.Ident); ok && ownerLocals[name.Name] {
					return true
				}
				// Present, but carrying something other than the client's
				// header: nil, a literal, a different variable.
				break
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
		t.Errorf("%s:%d: s3.%s does not carry the client's ExpectedBucketOwner — "+
			"every backend call carries the client's ownership precondition (ADR 0007 D14). "+
			"Set it in the literal: ExpectedBucketOwner: request.ExpectedBucketOwner(r)",
			m.file, m.line, m.typ)
	}
}

// isOwnerHeaderCall reports whether expr reads the client's ownership
// precondition: request.ExpectedBucketOwner(r), or ExpectedBucketOwner(r) from
// inside this package.
func isOwnerHeaderCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		return ok && pkg.Name == "request" && fn.Sel.Name == "ExpectedBucketOwner"
	case *ast.Ident:
		return fn.Name == "ExpectedBucketOwner"
	}
	return false
}
