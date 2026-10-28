package bus

import (
	"context"
	"errors"
	"fmt"
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

	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
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
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s: a key is a string literal", n.Name)
				}
				keys[n.Name], _ = strconv.Unquote(lit.Value)
			}
		}
	}
	return keys
}

// keyProblems checks one file of the package: an error is built with Connect (NewError, NewWireError, under
// whatever name connect is imported) only in errkeys.go; keyed and sourced take a key named directly from the
// registry or one of errkeys.go's key functions (keyFuncs), and sourced the one source constant; Key is never written
// outside errkeys.go (no conversion, no new constant). It returns the problems and how many keyed/sourced calls it
// checked.
func keyProblems(name string, src []byte, keys map[string]string, keyFuncs map[string]bool) (problems []string, checked int) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{err.Error()}, 0
	}
	registryFile := filepath.Base(name) == "errkeys.go"
	connectName := ""
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "connectrpc.com/connect" {
			connectName = "connect"
			if im.Name != nil {
				connectName = im.Name.Name
			}
		}
	}
	if connectName == "." {
		problems = append(problems, "a dot import of connect")
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && connectName != "" && id.Name == connectName && (x.Sel.Name == "NewError" || x.Sel.Name == "NewWireError") && !registryFile {
				problems = append(problems, "connect."+x.Sel.Name+" outside errkeys.go")
			}
		case *ast.CallExpr:
			fn, ok := x.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case (fn.Name == "keyed" || fn.Name == "sourced") && !registryFile: // keyed passes its own key on
				checked++
				ok := false
				switch k := x.Args[1].(type) {
				case *ast.Ident:
					ok = keys[k.Name] != ""
				case *ast.CallExpr:
					id, isID := k.Fun.(*ast.Ident)
					ok = isID && keyFuncs[id.Name]
				}
				if !ok {
					problems = append(problems, fn.Name+": a key that is not one of errkeys.go's constants or key functions")
				}
				if fn.Name == "sourced" {
					if id, isID := x.Args[2].(*ast.Ident); !isID || id.Name != "sourceStore" {
						problems = append(problems, "sourced: a source that is not sourceStore")
					}
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

// keyFuncs is errkeys.go's functions that return a Key.
func keyFuncs(t *testing.T) map[string]bool {
	f, err := parser.ParseFile(token.NewFileSet(), "errkeys.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fns := map[string]bool{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Type.Results != nil && len(fd.Type.Results.List) == 1 {
			if id, ok := fd.Type.Results.List[0].Type.(*ast.Ident); ok && id.Name == "Key" {
				fns[fd.Name.Name] = true
			}
		}
	}
	return fns
}

// TestErrKeys: every error the package answers is keyed from the closed registry; the keys are distinct and
// shaped "<area>.<what>".
func TestErrKeys(t *testing.T) {
	keys, fns := registry(t), keyFuncs(t)
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
		p, n := keyProblems(f, src, keys, fns)
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
	if len(keys) < 24 || checked < 28 || !fns["tokenKey"] {
		t.Errorf("%d keys, %d calls checked: the check no longer sees them", len(keys), checked) // the positive control
	}
}

// TestErrKeysForms: each form the check refuses, and the one it lets through.
func TestErrKeysForms(t *testing.T) {
	keys, fns := map[string]string{"keyA": "a.b"}, map[string]bool{"keyOf": true}
	for src, want := range map[string]int{
		`keyed(connect.CodeInternal, keyA, nil)`:                     0,
		`keyed(connect.CodeInternal, keyOf(nil), nil)`:               0,
		`keyed(connect.CodeInternal, other(nil), nil)`:               1,
		`sourced(connect.CodeInternal, keyA, sourceStore, nil)`:      0,
		`sourced(connect.CodeInternal, keyA, "pg", nil)`:             1,
		`connect.NewWireError(connect.CodeInternal, nil)`:            1,
		`keyed(connect.CodeInternal, keyB, nil)`:                     1,
		`keyed(connect.CodeInternal, "a.b", nil)`:                    1,
		`keyed(connect.CodeInternal, Key("a.b"), nil)`:               2,
		`connect.NewError(connect.CodeInternal, nil)`:                1,
		`func() { const keyC Key = "c.d"; _ = keyed(0, keyC, nil) }`: 2,
	} {
		p, _ := keyProblems("x.go", []byte("package bus\nimport \"connectrpc.com/connect\"\nvar _ = "+src+"\n"), keys, fns)
		if len(p) != want {
			t.Errorf("%s: %v, want %d problems", src, p, want)
		}
	}
	if p, _ := keyProblems("x.go", []byte("package bus\nimport cx \"connectrpc.com/connect\"\nvar _ = cx.NewError(0, nil)\n"), keys, fns); len(p) != 1 {
		t.Errorf("an aliased import: %v", p)
	}
}

// TestKeyed: the code and words are Connect's as before; the key and source ride as the detail.
func TestKeyed(t *testing.T) {
	e := sourced(connect.CodeUnavailable, keyStore, sourceStore, errors.New("conn refused"))
	if e.Code() != connect.CodeUnavailable || e.Message() != "conn refused" {
		t.Errorf("%v %q", e.Code(), e.Message())
	}
	if k, s, ok := keyOf(e); !ok || k != "store.unavailable" || s != "store" {
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
		{"bad token", f.publishErr(ctx, "unknown-token", ev), connect.CodeUnauthenticated, "auth.token_invalid", "unknown token"},
		{"hops", f.publishErr(ctx, "app-token", &bridgev1.CloudEvent{Id: "1", Type: "dev.app.x", Subject: "app/1", Hops: -1}), connect.CodeInvalidArgument, "publish.hops_out_of_range", "hops out of range"},
		{"data", f.publishErr(ctx, "app-token", &bridgev1.CloudEvent{Id: "1", Type: "dev.app.x", Subject: "app/1", Data: []byte("{")}), connect.CodeInvalidArgument, "publish.data_not_json", "data must be JSON"},
		{"subject", f.publishErr(ctx, "app-token", &bridgev1.CloudEvent{Id: "1", Type: "dev.app.x", Subject: "other/1"}), connect.CodePermissionDenied, "publish.subject_denied", "app may not publish on subject other/1"},
		{"gap unsent", func() error {
			_, err := f.api.ConfirmGap(ctx, as("app-token", &bridgev1.ConfirmGapRequest{Subscription: "app", Version: 5}))
			return err
		}(), connect.CodeFailedPrecondition, "gap.version_unsent", `gap version 5 was never sent on "app"`},
		{"not owned", func() error {
			_, err := f.api.ConfirmGap(ctx, as("app-token", &bridgev1.ConfirmGapRequest{Subscription: "bridge-core", Version: 1}))
			return err
		}(), connect.CodePermissionDenied, "auth.subscription_not_owned", `app may not use subscription "bridge-core"`},
		{"no subscription (a stream)", func() error {
			s, err := f.api.Replay(ctx, as("app-token", &bridgev1.ReplayRequest{Subscription: "app/none", FromSeq: 1}))
			if err != nil {
				return err
			}
			for s.Receive() {
			}
			return s.Err()
		}(), connect.CodeNotFound, "replay.no_subscription", `no subscription "app/none"`},
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

// TestWireRefused: the store's own refusal (text holds no NUL) is keyed publish.refused, with its source.
func TestWireRefused(t *testing.T) {
	f := setup(t)
	err := f.publishErr(context.Background(), "app-token", &bridgev1.CloudEvent{Id: "1", Type: "dev.app.x", Subject: "app/\x00"})
	if k, src, ok := keyOf(err); !ok || k != "publish.refused" || src != "store" || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("%v: key %q source %q", err, k, src)
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

// TestTokenKey: a refused token is keyed by why: the bridge unpinned, the token expired, anything else.
func TestTokenKey(t *testing.T) {
	for err, want := range map[error]Key{
		auth.ErrNoKey: keyNoKey, fmt.Errorf("verify: %w", auth.ErrExpired): keyExpired, errors.New("token: no sub"): keyToken,
	} {
		if got := tokenKey(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

// TestKeyAll: what a handler returns without a key leaves keyed internal, with its code and words; a keyed error
// keeps its own key; nil stays nil.
func TestKeyAll(t *testing.T) {
	plain := withKey(errors.New("send: broken pipe"))
	if k, _, ok := keyOf(plain); !ok || k != "server.internal" || connect.CodeOf(plain) != connect.CodeUnknown || !strings.Contains(plain.Error(), "send: broken pipe") {
		t.Errorf("plain: %v key %q", plain, k)
	}
	bare := withKey(connect.NewError(connect.CodeResourceExhausted, errors.New("too big")))
	if k, _, ok := keyOf(bare); !ok || k != "server.internal" || connect.CodeOf(bare) != connect.CodeResourceExhausted {
		t.Errorf("bare: %v key %q", bare, k)
	}
	own := withKey(keyed(connect.CodeAborted, keyGapped, errGapped))
	var ce *connect.Error
	if k, _, _ := keyOf(own); k != "stream.gapped" || !errors.As(own, &ce) || len(ce.Details()) != 1 {
		t.Errorf("own: key %q", k) // the positive control: a keyed error is left alone, one detail
	}
	if withKey(nil) != nil {
		t.Error("nil became an error")
	}
}

// TestKeyAllWraps: both of keyAll's handler wrappers key a raw error, and Handler installs keyAll.
func TestKeyAllWraps(t *testing.T) {
	raw := errors.New("raw")
	unary := keyAll{}.WrapUnary(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) { return nil, raw })
	if _, err := unary(context.Background(), nil); func() string { k, _, _ := keyOf(err); return k }() != "server.internal" {
		t.Errorf("unary: %v", err)
	}
	stream := keyAll{}.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error { return raw })
	if err := stream(context.Background(), nil); func() string { k, _, _ := keyOf(err); return k }() != "server.internal" {
		t.Errorf("stream: %v", err)
	}
	src, err := os.ReadFile("bus.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "NewBridgeServiceHandler(s, connect.WithInterceptors(append(ics, keyAll{})...))") {
		t.Error("Handler does not install keyAll")
	}
}
