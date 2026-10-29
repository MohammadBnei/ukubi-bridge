package bus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/MohammadBnei/ukubi-go/errs/connectkeys"
	errorsv1 "github.com/MohammadBnei/ukubi-go/proto/gen/go/ukubi/errors/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
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

// twinned: err's bridge.v1.ErrorKey detail is followed by a ukubi.errors.v1.ErrorKey one with the same bytes, as a
// client of either name reads it (standard §6: both, the old one first).
func twinned(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return false
	}
	ds := ce.Details()
	for i, d := range ds {
		if d.Type() == "bridge.v1.ErrorKey" {
			if i+1 == len(ds) || ds[i+1].Type() != "ukubi.errors.v1.ErrorKey" || string(ds[i+1].Bytes()) != string(d.Bytes()) {
				return false
			}
			v, err := ds[i+1].Value()
			_, isKey := v.(*errorsv1.ErrorKey)
			return err == nil && isKey
		}
	}
	return false
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

// keyProblems checks one file of the package: an error or an error detail is built with Connect (NewError,
// NewWireError, NewErrorDetail, under whatever name connect is imported) only in errkeys.go; keyed and sourced take a
// key named directly from the registry or one of errkeys.go's key functions (keyFuncs), and sourced the one source
// constant; Key is never written outside errkeys.go (no conversion, no new constant); the identifier keys (the
// connectkeys.Keys, in any use: a call, an alias, a field) and ukubi-go's errs, connectkeys and ukubi.errors.v1
// packages appear only in errkeys.go. It returns the problems and how many keyed/sourced calls it checked.
func keyProblems(name string, src []byte, keys map[string]string, keyFuncs map[string]bool) (problems []string, checked int) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{err.Error()}, 0
	}
	registryFile := filepath.Base(name) == "errkeys.go"
	connectName := ""
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if (p == "github.com/MohammadBnei/ukubi-go/errs" || p == "github.com/MohammadBnei/ukubi-go/errs/connectkeys" ||
			p == "github.com/MohammadBnei/ukubi-go/proto/gen/go/ukubi/errors/v1") && !registryFile {
			problems = append(problems, "an import of "+p+" outside errkeys.go")
		}
		if p == "connectrpc.com/connect" {
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
			if id, ok := x.X.(*ast.Ident); ok && connectName != "" && id.Name == connectName && !registryFile &&
				(x.Sel.Name == "NewError" || x.Sel.Name == "NewWireError" || x.Sel.Name == "NewErrorDetail") {
				problems = append(problems, "connect."+x.Sel.Name+" outside errkeys.go")
			}
		case *ast.Ident:
			if x.Name == "keys" && !registryFile {
				problems = append(problems, "keys outside errkeys.go")
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
		`keys.Connect(connect.CodeInternal, keyA, nil)`:              1,
		`keys.Sourced(connect.CodeInternal, keyA, sourceStore, nil)`: 1,
		`keys.Status(0, keyA, "x")`:                                  1,
		`keys.WithInterceptors()`:                                    1,
		`func() { k := keys; _ = k.Connect(0, keyA, nil) }`:          1,
		`connect.NewErrorDetail(nil)`:                                1,
	} {
		p, _ := keyProblems("x.go", []byte("package bus\nimport \"connectrpc.com/connect\"\nvar _ = "+src+"\n"), keys, fns)
		if len(p) != want {
			t.Errorf("%s: %v, want %d problems", src, p, want)
		}
	}
	if p, _ := keyProblems("x.go", []byte("package bus\nimport cx \"connectrpc.com/connect\"\nvar _ = cx.NewError(0, nil)\n"), keys, fns); len(p) != 1 {
		t.Errorf("an aliased import: %v", p)
	}
	for _, im := range []string{`"github.com/MohammadBnei/ukubi-go/errs"`, `ck "github.com/MohammadBnei/ukubi-go/errs/connectkeys"`,
		`ev1 "github.com/MohammadBnei/ukubi-go/proto/gen/go/ukubi/errors/v1"`} {
		if p, _ := keyProblems("x.go", []byte("package bus\nimport "+im+"\n"), keys, fns); len(p) != 1 {
			t.Errorf("%s: %v, want 1 problem", im, p)
		}
		if p, _ := keyProblems("errkeys.go", []byte("package bus\nimport "+im+"\nvar _ = keys.Connect\n"), keys, fns); len(p) != 0 {
			t.Errorf("%s in errkeys.go: %v", im, p) // the positive control: the registry file may
		}
	}
}

// TestKeyInternal: the registry's keyInternal is the key connectkeys' fallback puts.
func TestKeyInternal(t *testing.T) {
	if keyInternal != connectkeys.KeyInternal {
		t.Errorf("%q, connectkeys puts %q", keyInternal, connectkeys.KeyInternal)
	}
}

// TestKeyed: the code and words are Connect's as before; the key and source ride as the detail.
func TestKeyed(t *testing.T) {
	e := sourced(connect.CodeUnavailable, keyStore, sourceStore, errors.New("conn refused"))
	if e.Code() != connect.CodeUnavailable || e.Message() != "conn refused" {
		t.Errorf("%v %q", e.Code(), e.Message())
	}
	if k, s, ok := keyOf(e); !ok || k != "store.unavailable" || s != "store" || !twinned(e) {
		t.Errorf("key %q source %q %v twinned %v", k, s, ok, twinned(e))
	}
	g := keyed(connect.CodeAborted, keyGapped, errGapped)
	if k, s, ok := keyOf(g); !ok || k != "stream.gapped" || s != "" || !twinned(g) || len(g.Details()) != 2 {
		t.Errorf("key %q source %q %v twinned %v", k, s, ok, twinned(g))
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
		if !ok || k != c.key || connect.CodeOf(c.err) != c.code || ce == nil || ce.Message() != c.msg || !twinned(c.err) {
			t.Errorf("%s: %v key %q twinned %v", c.name, c.err, k, twinned(c.err))
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

// fallbackStub answers Publish and Subscribe with err, whatever it is.
type fallbackStub struct {
	bridgev1connect.UnimplementedBridgeServiceHandler
	err error
}

func (f fallbackStub) Publish(context.Context, *connect.Request[bridgev1.PublishRequest]) (*connect.Response[bridgev1.PublishResponse], error) {
	return nil, f.err
}

func (f fallbackStub) Subscribe(context.Context, *connect.Request[bridgev1.SubscribeRequest], *connect.ServerStream[bridgev1.SubscribeResponse]) error {
	return f.err
}

// TestFallback: mounted with Handler's option, what a handler returns without a key (unary or streaming) reaches a
// client keyed internal, as both details, with its code and words; a keyed error keeps its own key and two details; a
// shared sentinel is never changed, under concurrent requests (run with -race). connectkeys' own tests hold the table
// (context codes, copies, the outermost order); this holds the bridge's wiring of it.
func TestFallback(t *testing.T) {
	why, err := connect.NewErrorDetail(wrapperspb.String("gone"))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := connect.NewError(connect.CodeNotFound, errors.New("no such subscription"))
	sentinel.Meta().Set("X-Why", "gone")
	sentinel.AddDetail(why)
	for _, c := range []struct {
		name    string
		err     error
		code    connect.Code
		key     string
		msg     string
		details int
	}{
		{"raw", errors.New("send: broken pipe"), connect.CodeUnknown, "server.internal", "send: broken pipe", 2},
		{"deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), connect.CodeDeadlineExceeded, "server.internal", "query: context deadline exceeded", 2},
		{"canceled", fmt.Errorf("send: %w", context.Canceled), connect.CodeCanceled, "server.internal", "send: context canceled", 2},
		{"sentinel", sentinel, connect.CodeNotFound, "server.internal", "no such subscription", 3},
		{"keyed", keyed(connect.CodeAborted, keyGapped, errGapped), connect.CodeAborted, "stream.gapped", errGapped.Error(), 2}, // the positive control
	} {
		mux := http.NewServeMux()
		mux.Handle(bridgev1connect.NewBridgeServiceHandler(fallbackStub{err: c.err}, withInterceptors()))
		srv := httptest.NewServer(mux)
		api := bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL)
		var wg sync.WaitGroup
		check := func(form string, got error) {
			defer wg.Done()
			var ce *connect.Error
			if k, _, ok := keyOf(got); !ok || k != c.key || !twinned(got) || connect.CodeOf(got) != c.code || !errors.As(got, &ce) ||
				ce.Message() != c.msg || len(ce.Details()) != c.details {
				t.Errorf("%s %s: %v key %q", c.name, form, got, k)
				return
			}
			if c.err == sentinel && (ce.Meta().Get("X-Why") != "gone" || ce.Details()[0].Type() != why.Type()) {
				t.Errorf("%s %s: the sentinel's meta or detail was lost: %v", c.name, form, got)
			}
		}
		for range 10 {
			wg.Add(2)
			go func() {
				_, err := api.Publish(context.Background(), connect.NewRequest(&bridgev1.PublishRequest{}))
				check("unary", err)
			}()
			go func() {
				s, err := api.Subscribe(context.Background(), connect.NewRequest(&bridgev1.SubscribeRequest{}))
				if err == nil {
					for s.Receive() {
					}
					err = s.Err()
				}
				check("stream", err)
			}()
		}
		wg.Wait()
		srv.Close()
	}
	if _, _, ok := keyOf(sentinel); ok || len(sentinel.Details()) != 1 || sentinel.Meta().Get("X-Why") != "gone" {
		t.Errorf("the sentinel was changed: %d details", len(sentinel.Details()))
	}
}

// TestHandlerFallback: the real Server.Handler puts the key fallback outside every interceptor it is given: an
// interceptor sees an unkeyed error, and the client gets it keyed server.internal, as both details.
func TestHandlerFallback(t *testing.T) {
	var seen error
	record := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			res, err := next(ctx, req)
			seen = err
			return res, err
		}
	})
	raw := connect.UnaryInterceptorFunc(func(connect.UnaryFunc) connect.UnaryFunc {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, errors.New("inner: raw")
		}
	})
	mux := http.NewServeMux()
	mux.Handle(New(nil, nil, nil).Handler(record, raw)) // raw never calls next: no store is reached
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL).Publish(context.Background(), connect.NewRequest(&bridgev1.PublishRequest{}))
	if _, _, ok := keyOf(seen); ok || seen == nil || seen.Error() != "inner: raw" {
		t.Errorf("the recording interceptor saw %v, want the unkeyed error", seen)
	}
	if k, _, ok := keyOf(err); !ok || k != "server.internal" || !twinned(err) {
		t.Errorf("%v: key %q, want server.internal as both details", err, k)
	}
}

// TestFallbackInterceptors: an interceptor inside the fallback sees the handler's error before it is keyed, and what
// the interceptor itself returns unkeyed is keyed internal, as both details.
func TestFallbackInterceptors(t *testing.T) {
	var seen error
	ic := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			_, seen = next(ctx, req)
			return nil, errors.New("interceptor: broken")
		}
	})
	mux := http.NewServeMux()
	mux.Handle(bridgev1connect.NewBridgeServiceHandler(fallbackStub{err: errors.New("handler: raw")}, withInterceptors(ic)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL).Publish(context.Background(), connect.NewRequest(&bridgev1.PublishRequest{}))
	if _, _, ok := keyOf(seen); ok || seen == nil || seen.Error() != "handler: raw" {
		t.Errorf("the interceptor saw %v, want the handler's unkeyed error", seen)
	}
	var ce *connect.Error
	if k, _, ok := keyOf(err); !ok || k != "server.internal" || !twinned(err) || !errors.As(err, &ce) || ce.Message() != "interceptor: broken" {
		t.Errorf("%v: key %q", err, k)
	}
}

// wireDetail is a detail of a Connect protocol error body.
type wireDetail struct{ Type, Value string }

// TestFallbackMalformed: an unreadable unary request is refused by Connect before the handler chain, so it carries no
// key; a stream's is read inside the chain, so it is keyed server.internal, as both details, with Connect's code.
func TestFallbackMalformed(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(bridgev1connect.NewBridgeServiceHandler(fallbackStub{err: errors.New("unreached")}, withInterceptors()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := srv.Client().Post(srv.URL+bridgev1connect.BridgeServicePublishProcedure, "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	var unary struct {
		Code    string
		Details []wireDetail
	}
	if err := json.NewDecoder(res.Body).Decode(&unary); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if unary.Code != "invalid_argument" || len(unary.Details) != 0 {
		t.Errorf("unary: %+v, want invalid_argument with no detail", unary)
	}

	env := make([]byte, 5, 6)
	binary.BigEndian.PutUint32(env[1:], 1)
	res, err = srv.Client().Post(srv.URL+bridgev1connect.BridgeServiceSubscribeProcedure, "application/connect+json", bytes.NewReader(append(env, '{')))
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(res.Body)
	_ = res.Body.Close()
	b := body.Bytes()
	if len(b) < 5 || b[0]&2 == 0 {
		t.Fatalf("stream: %q, want an end-stream message", b)
	}
	var end struct {
		Error struct {
			Code    string
			Details []wireDetail
		}
	}
	if err := json.Unmarshal(b[5:], &end); err != nil {
		t.Fatal(err)
	}
	ds := end.Error.Details
	if end.Error.Code != "invalid_argument" || len(ds) != 2 || ds[0].Type != "bridge.v1.ErrorKey" ||
		ds[1].Type != "ukubi.errors.v1.ErrorKey" || ds[0].Value != ds[1].Value {
		t.Fatalf("stream: %+v, want invalid_argument with both details", end.Error)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(ds[0].Value, "="))
	var k bridgev1.ErrorKey
	if err != nil || proto.Unmarshal(raw, &k) != nil || k.GetKey() != "server.internal" {
		t.Errorf("stream: key %q (%v)", k.GetKey(), err)
	}
}
