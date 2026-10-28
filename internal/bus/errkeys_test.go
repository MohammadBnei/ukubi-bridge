package bus

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
)

// keyOf is the ErrorKey an error carries, as a client reads it.
func keyOf(err error) (key, source string, ok bool) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return "", "", false
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if k, isKey := v.(*bridgev1.ErrorKey); isKey {
				return k.GetKey(), k.GetSource(), true
			}
		}
	}
	return "", "", false
}

// registry is errkeys.go's Key constants: name -> value.
func registry(t *testing.T) map[string]string {
	f, err := parser.ParseFile(token.NewFileSet(), "errkeys.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Key" {
				continue
			}
			for i, n := range v.Names {
				keys[n.Name], _ = strconv.Unquote(v.Values[i].(*ast.BasicLit).Value)
			}
		}
	}
	return keys
}

// keyProblems checks one file of the package: an error is built only by keyed or sourced, with a key named
// directly from the registry, and Key is never written outside errkeys.go (no conversion, no new constant).
// It returns the problems and how many keyed/sourced calls it checked.
func keyProblems(name string, src []byte, keys map[string]string) (problems []string, checked int) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{err.Error()}, 0
	}
	registryFile := filepath.Base(name) == "errkeys.go"
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "connect" && x.Sel.Name == "NewError" && !registryFile {
				problems = append(problems, "connect.NewError outside errkeys.go")
			}
		case *ast.CallExpr:
			fn, ok := x.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case (fn.Name == "keyed" || fn.Name == "sourced") && !registryFile: // keyed passes its own key on
				checked++
				if id, ok := x.Args[1].(*ast.Ident); !ok || keys[id.Name] == "" {
					problems = append(problems, fn.Name+": a key that is not one of errkeys.go's constants")
				}
			case fn.Name == "Key" && !registryFile:
				problems = append(problems, "a Key conversion outside errkeys.go")
			}
		case *ast.ValueSpec:
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Key" && !registryFile {
				problems = append(problems, "a Key declared outside errkeys.go")
			}
		}
		return true
	})
	return problems, checked
}

// TestErrKeys: every error the package answers is keyed from the closed registry; the keys are distinct and
// shaped "<area>.<what>".
func TestErrKeys(t *testing.T) {
	keys := registry(t)
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p, n := keyProblems(f, src, keys)
		checked += n
		for _, e := range p {
			t.Errorf("%s: %s", f, e)
		}
	}
	seen := map[string]string{}
	shape := regexp.MustCompile(`^[a-z]+\.[a-z_]+$`)
	for name, v := range keys {
		if !shape.MatchString(v) {
			t.Errorf("%s = %q: not <area>.<what>", name, v)
		}
		if other := seen[v]; other != "" {
			t.Errorf("%s and %s are both %q", name, other, v)
		}
		seen[v] = name
	}
	if len(keys) < 22 || checked < 28 {
		t.Errorf("%d keys, %d calls checked: the check no longer sees them", len(keys), checked) // the positive control
	}
}

// TestErrKeysForms: each form the check refuses, and the one it lets through.
func TestErrKeysForms(t *testing.T) {
	keys := map[string]string{"keyA": "a.b"}
	for src, want := range map[string]int{
		`keyed(connect.CodeInternal, keyA, nil)`:                     0,
		`sourced(connect.CodeInternal, keyA, "postgres", nil)`:       0,
		`keyed(connect.CodeInternal, keyB, nil)`:                     1,
		`keyed(connect.CodeInternal, "a.b", nil)`:                    1,
		`keyed(connect.CodeInternal, Key("a.b"), nil)`:               2,
		`connect.NewError(connect.CodeInternal, nil)`:                1,
		`func() { const keyC Key = "c.d"; _ = keyed(0, keyC, nil) }`: 2,
	} {
		p, _ := keyProblems("x.go", []byte("package bus\nvar _ = "+src+"\n"), keys)
		if len(p) != want {
			t.Errorf("%s: %v, want %d problems", src, p, want)
		}
	}
}

// TestKeyed: the code and words are Connect's as before; the key and source ride as the detail.
func TestKeyed(t *testing.T) {
	e := sourced(connect.CodeUnavailable, keyStore, sourcePostgres, errors.New("conn refused"))
	if e.Code() != connect.CodeUnavailable || e.Message() != "conn refused" {
		t.Errorf("%v %q", e.Code(), e.Message())
	}
	if k, s, ok := keyOf(e); !ok || k != "store.unavailable" || s != "postgres" {
		t.Errorf("key %q source %q %v", k, s, ok)
	}
	if k, s, ok := keyOf(keyed(connect.CodeAborted, keyGapped, errGapped)); !ok || k != "stream.gapped" || s != "" {
		t.Errorf("key %q source %q %v", k, s, ok)
	}
}

// TestWireKeys: over the real API and a Connect client, a call's error carries its key, with the code and message
// it had before.
func TestWireKeys(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ev := &bridgev1.CloudEvent{Id: "1", Type: "dev.app.x", Subject: "app/1"}
	for _, c := range []struct {
		name string
		err  error
		code connect.Code
		key  string
		msg  string
	}{
		{"no bearer", f.publishErr(ctx, "", ev), connect.CodeUnauthenticated, "auth.bearer_required", "bearer token required"},
		{"not a client", f.publishErr(ctx, "nobody-token", ev), connect.CodeUnauthenticated, "auth.not_a_client", "nobody is not a bridge client"},
		{"fields", f.publishErr(ctx, "app-token", &bridgev1.CloudEvent{Id: "1"}), connect.CodeInvalidArgument, "publish.fields_required", "id, type and subject are required"},
		{"type", f.publishErr(ctx, "app-token", &bridgev1.CloudEvent{Id: "1", Type: "dev.other", Subject: "app/1"}), connect.CodePermissionDenied, "publish.type_denied", "app may not publish dev.other"},
		{"gap version", func() error {
			_, err := f.api.ConfirmGap(ctx, as("app-token", &bridgev1.ConfirmGapRequest{Subscription: "app", Version: 0}))
			return err
		}(), connect.CodeInvalidArgument, "gap.version_invalid", "version must be positive"},
	} {
		k, _, ok := keyOf(c.err)
		var ce *connect.Error
		errors.As(c.err, &ce)
		if !ok || k != c.key || connect.CodeOf(c.err) != c.code || ce == nil || ce.Message() != c.msg {
			t.Errorf("%s: %v key %q", c.name, c.err, k)
		}
	}
}

func (f fixture) publishErr(ctx context.Context, tok string, e *bridgev1.CloudEvent) error {
	req := connect.NewRequest(&bridgev1.PublishRequest{Event: e})
	if tok != "" {
		req.Header().Set("Authorization", "Bearer "+tok)
	}
	_, err := f.api.Publish(ctx, req)
	return err
}
