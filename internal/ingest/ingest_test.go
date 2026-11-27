package ingest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/metrics"
)

const (
	session = "11111111-2222-4333-8444-555555555555"
	postID  = "66666666-7777-4888-9999-000000000000"
	other   = "66666666-7777-4888-9999-000000000001"
)

var (
	now   = time.Date(2026, 11, 24, 12, 0, 30, 0, time.UTC)
	repos = map[string]bool{"o/r": true}
)

// body is a good body with changes; a nil value removes the field.
func body(t *testing.T, changes map[string]any) []byte {
	m := map[string]any{"session": session, "session_label": "feed", "repo": "o/r", "branch": "feat/x", "post_id": postID, "text": "Done.",
		"about": []any{map[string]any{"repo": "o/r", "number": 7}}, "needs_you": []string{"merge #7"}, "corrects": other}
	maps.Copy(m, changes)
	maps.DeleteFunc(m, func(_ string, v any) bool { return v == nil })
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func build(t *testing.T, changes map[string]any) (event.Event, map[string]any, []string) {
	t.Helper()
	e, masked, err := Post(context.Background(), body(t, changes), repos, now)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(e.Data, &d); err != nil {
		t.Fatal(err)
	}
	return e, d, masked
}

func TestPost(t *testing.T) {
	e, d, masked := build(t, nil)
	if e.ID != "post/"+session+"/"+postID || e.Source != "ingest/laptop" || e.Type != PostCreated || e.Subject != "laptop/session/"+session ||
		!e.Time.Equal(now) || e.Actor != event.ActorMachine || masked != nil {
		t.Errorf("%+v, masked %v", e, masked)
	}
	if e.ActorLogin != "" || e.ActorTrusted || e.ThreadOwned || e.Owner != "" || e.Hops != 0 || e.CausationID != "" || e.Replayed {
		t.Errorf("a trust attribute is set: %+v", e)
	}
	want := map[string]any{"session": session, "session_label": "feed", "repo": "o/r", "branch": "feat/x", "post_id": postID, "text": "Done.",
		"about": []any{map[string]any{"repo": "o/r", "number": 7.0}}, "needs_you": []any{"merge #7"}, "corrects": other}
	if !reflect.DeepEqual(d, want) {
		t.Errorf("%v, want %v", d, want)
	}
	t.Cleanup(contract.Reset)
	if err := contract.Load("../../contract/events.yaml"); err != nil || !contract.Known(e.Type) {
		t.Errorf("%s is not in contract/events.yaml (%v)", e.Type, err)
	}
	// Only the ids and the text are required, and an absent field stays absent.
	_, d, _ = build(t, map[string]any{"session_label": nil, "repo": nil, "branch": nil, "about": nil, "needs_you": nil, "corrects": nil})
	if !reflect.DeepEqual(d, map[string]any{"session": session, "post_id": postID, "text": "Done."}) {
		t.Errorf("%v", d)
	}
}

// An empty needs_you clears, so it is not an absent one, here and in the store.
func TestNeedsYouEmpty(t *testing.T) {
	_, d, _ := build(t, map[string]any{"needs_you": []string{}})
	if v, ok := d["needs_you"]; !ok || !reflect.DeepEqual(v, []any{}) {
		t.Errorf("empty: %v %v", v, ok)
	}
	_, d, _ = build(t, map[string]any{"needs_you": nil})
	if v, ok := d["needs_you"]; ok {
		t.Errorf("absent: %v", v)
	}
}

// Every refusal of a body, one change from a good one, and the field its answer names.
func TestPostRefuses(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a ", n/2+1)[:n] }
	ref := func(repo, n any) []any { return []any{map[string]any{"repo": repo, "number": n}} }
	for name, c := range map[string]struct {
		changes map[string]any
		names   string
	}{
		"unknown field": {map[string]any{"x": 1}, "body"}, "cwd": {map[string]any{"cwd": "/x"}, "body"}, "prompt": {map[string]any{"prompt": "x"}, "body"},
		"transcript": {map[string]any{"transcript_path": "/x"}, "body"}, "env": {map[string]any{"env": map[string]string{}}, "body"},
		"actor": {map[string]any{"actor": "human"}, "body"}, "actor_trusted": {map[string]any{"actor_trusted": true}, "body"},
		"thread_owned": {map[string]any{"thread_owned": true}, "body"}, "source": {map[string]any{"source": "x"}, "body"}, "hops": {map[string]any{"hops": 1}, "body"},
		"owner": {map[string]any{"owner": "x"}, "body"}, "truncated": {map[string]any{"truncated": true}, "body"}, "other case": {map[string]any{"Text": "x"}, "body"},
		"about unknown": {map[string]any{"about": []any{map[string]any{"repo": "o/r", "number": 1, "x": 1}}}, "body"},
		"null":          {map[string]any{"needs_you": json.RawMessage("null")}, "body"}, "null text": {map[string]any{"text": json.RawMessage("null")}, "body"},
		"no session": {map[string]any{"session": nil}, "session"}, "session not a uuid": {map[string]any{"session": "x"}, "session"}, "session upper": {map[string]any{"session": "A" + session[1:]}, "session"},
		"session longer": {map[string]any{"session": session + "0"}, "session"}, "session number": {map[string]any{"session": 1}, "body"}, "session path": {map[string]any{"session": "../x"}, "session"},
		"label long": {map[string]any{"session_label": long(201)}, "session_label"}, "label number": {map[string]any{"session_label": 1}, "body"}, "repo long": {map[string]any{"repo": long(201)}, "repo"}, "repo list": {map[string]any{"repo": []string{"x"}}, "body"},
		"branch long": {map[string]any{"branch": long(201)}, "branch"}, "branch number": {map[string]any{"branch": 1}, "body"},
		"no post_id": {map[string]any{"post_id": nil}, "post_id"}, "post_id not a uuid": {map[string]any{"post_id": postID + "/x"}, "post_id"},
		"no text": {map[string]any{"text": nil}, "text"}, "empty text": {map[string]any{"text": ""}, "text"}, "blank text": {map[string]any{"text": " \n\u200b\t"}, "text"},
		"text 4001 as sent": {map[string]any{"text": long(maxText) + "\u200b"}, "text: 4001 characters"}, "text 4001": {map[string]any{"text": long(maxText) + "a"}, "text: 4001 characters, the limit is 4000"}, "text number": {map[string]any{"text": 1}, "body"},
		"text over once masked": {map[string]any{"text": long(maxText-10) + " pin: 4821"}, "text: 4004 characters"},
		"about object":          {map[string]any{"about": map[string]any{}}, "body"}, "about many": {map[string]any{"about": slices.Repeat(ref("o/r", 1), 11)}, "about"},
		"about unlisted": {map[string]any{"about": ref("o/x", 1)}, "about[0].repo"}, "about other case": {map[string]any{"about": ref("O/r", 1)}, "about[0].repo"},
		"about null": {map[string]any{"about": ref(nil, 1)}, "about[0].repo"}, "about alert": {map[string]any{"about": []any{map[string]any{"alert": "x"}}}, "body"},
		"about zero": {map[string]any{"about": ref("o/r", 0)}, "about[0].number"}, "about negative": {map[string]any{"about": ref("o/r", -1)}, "about[0].number"},
		"about huge": {map[string]any{"about": ref("o/r", 1_000_000_000)}, "about[0].number"}, "about half": {map[string]any{"about": ref("o/r", 1.5)}, "body"}, "about string": {map[string]any{"about": ref("o/r", "1")}, "body"},
		"needs string": {map[string]any{"needs_you": "x"}, "body"}, "needs many": {map[string]any{"needs_you": slices.Repeat([]string{"x"}, 11)}, "needs_you"},
		"needs long": {map[string]any{"needs_you": []string{"x", long(200) + "a"}}, "needs_you[1]"}, "needs empty": {map[string]any{"needs_you": []string{""}}, "needs_you[0]"},
		"needs blank": {map[string]any{"needs_you": []string{" \u200b"}}, "needs_you[0]"}, "needs null": {map[string]any{"needs_you": []any{nil}}, "needs_you[0]"},
		"corrects not a uuid": {map[string]any{"corrects": "x"}, "corrects"}, "corrects itself": {map[string]any{"corrects": postID}, "corrects"},
	} {
		if _, _, err := Post(context.Background(), body(t, c.changes), repos, now); err == nil || !strings.HasPrefix(err.Error(), c.names) {
			t.Errorf("%s: %v, want %s", name, err, c.names)
		}
	}
	good := string(body(t, nil))
	for name, b := range map[string]string{"empty": "", "null": "null", "list": "[]", "string": `"x"`, "open": good[:len(good)-1], "trailing": good + "{}", "brace": good + "}",
		"twice": `{"repo":"o/r",` + good[1:], "utf-8": strings.Replace(good, "Done.", "Done\xff", 1)} {
		if _, _, err := Post(context.Background(), []byte(b), repos, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The positive control, each bound included.
	for name, c := range map[string]map[string]any{
		"as is": {}, "text 1": {"text": "x"}, "text 4000": {"text": strings.Repeat("é ", maxText/2-1) + "éé"}, "label 200": {"session_label": long(199) + "a"},
		"bounds": {"repo": long(199) + "a", "branch": long(199) + "a", "about": slices.Repeat(ref("o/r", maxNumber), 10), "needs_you": slices.Repeat([]string{long(199) + "a"}, 10)},
	} {
		if _, _, err := Post(context.Background(), body(t, c), repos, now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := Post(context.Background(), []byte(good), nil, now); err == nil || !strings.HasPrefix(err.Error(), "about[0].repo") {
		t.Errorf("no repo is listed: %v", err)
	}
}

// What is stored is masked, and the answer names the fields.
func TestPostMasks(t *testing.T) {
	s := "ghp_" + fake(alnum, 20)
	e, d, masked := build(t, map[string]any{"repo": s, "branch": "feat " + s + "\u200b\n x", "session_label": "a " + s, "needs_you": []string{"fine", "use " + s},
		"text": "a\u202e **b**\n\n\t- token: " + s + "\n\nand so on"})
	if leak(s[4:], string(e.Data)+e.ID, 5) != "" {
		t.Errorf("%s", e.Data)
	}
	if d["repo"] != "ghp_[masked]" || d["branch"] != "feat ghp_[masked]" || d["session_label"] != "a ghp_[masked]" || !reflect.DeepEqual(d["needs_you"], []any{"fine", "use ghp_[masked]"}) ||
		d["text"] != "a **b**\n\n\t- token: [masked]\n\nand so on" {
		t.Errorf("%v", d)
	}
	if want := []string{"text", "session_label", "repo", "branch", "needs_you[1]"}; !slices.Equal(masked, want) {
		t.Errorf("masked %v, want %v", masked, want)
	}
	if _, _, masked := build(t, map[string]any{"text": "a\u200bb\r\n"}); masked != nil {
		t.Errorf("masked %v", masked)
	}
	for pad := maxLabel - len(s); pad <= maxLabel; pad++ {
		_, d, _ := build(t, map[string]any{"session_label": strings.Repeat("- ", pad/2) + strings.Repeat("-", pad%2) + " " + s})
		if l := d["session_label"].(string); leak(s[4:], l, 3) != "" || len(l) > maxLabel {
			t.Errorf("at %d: %q", pad, l)
		}
	}
}

// A post's id is the sender's: a retry is the same event whatever else changed, another post_id or session is not.
func TestPostID(t *testing.T) {
	id := func(c map[string]any) string { e, _, _ := build(t, c); return e.ID }
	if id(nil) != id(map[string]any{"text": "other", "about": nil}) {
		t.Error("a retry is a new event")
	}
	if id(nil) == id(map[string]any{"post_id": session}) || id(nil) == id(map[string]any{"session": postID}) {
		t.Error("two posts are one event")
	}
}

func sign(key []byte, source, ts string, b []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(source + "\n" + ts + "\n"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func signed(key, b []byte, at time.Time) *http.Request {
	ts := strconv.FormatInt(at.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/ingest/laptop", bytes.NewReader(b))
	r.Header.Set(TimestampHeader, ts)
	r.Header.Set(SignatureHeader, sign(key, LaptopSource, ts, b))
	return r
}

func TestVerify(t *testing.T) {
	key, b := []byte(fake(hexes, 64)), []byte(`{}`)
	good := sign(key, LaptopSource, "1", b)
	if !Verify(key, LaptopSource, "1", b, good) {
		t.Fatal("a good signature is refused")
	}
	for name, ok := range map[string]bool{
		"empty": Verify(key, LaptopSource, "1", b, ""), "not hex": Verify(key, LaptopSource, "1", b, "zz"), "short": Verify(key, LaptopSource, "1", b, good[:62]),
		"prefixed": Verify(key, LaptopSource, "1", b, "sha256="+good), "other key": Verify([]byte("k"), LaptopSource, "1", b, good),
		"other source": Verify(key, "ingest/other", "1", b, good), "other time": Verify(key, LaptopSource, "2", b, good),
		"other body": Verify(key, LaptopSource, "1", []byte(`{} `), good), "body alone": Verify(key, LaptopSource, "1", b, hex.EncodeToString(hmacOf(key, b))),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func hmacOf(key, b []byte) []byte { m := hmac.New(sha256.New, key); m.Write(b); return m.Sum(nil) }

// The signature is compared in constant time: Verify returns hmac.Equal, and compares nothing but errors itself.
func TestVerifyConstantTime(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "ingest.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	equal := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Verify" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if id, ok := x.X.(*ast.Ident); (x.Op == token.EQL || x.Op == token.NEQ) && (!ok || id.Name != "err") {
					t.Error("Verify compares with ==")
				}
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "hmac" && x.Sel.Name == "Equal" {
					equal++
				} else if ok && (id.Name == "bytes" || id.Name == "strings") {
					t.Errorf("Verify calls %s.%s", id.Name, x.Sel.Name)
				}
			}
			return true
		})
	}
	if equal != 1 {
		t.Errorf("%d hmac.Equal calls in Verify", equal)
	}
}

func TestFresh(t *testing.T) {
	at := time.Unix(1_000_000, 900_000_000)
	for ts, want := range map[string]bool{"1000000": true, "999700": true, "999699": false, "1000300": true, "1000301": false, "0": false, "": false, "x": false,
		"1000000.0": false, " 1000000": false, "-1000000": false, "9223372036854775807": false, "-9223372036854775808": false, "99999999999999999999": false} {
		if got := fresh(ts, at); got != want {
			t.Errorf("%q: %v", ts, got)
		}
	}
}

// logs captures the default logger for the test.
func logs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// Every answer of the route: its status, its metric, and nothing of the body in a log line, an answer or a label.
func TestHandler(t *testing.T) {
	key, secret := []byte(fake(hexes, 64)), "ghp_"+fake(alnum, 20)
	good := body(t, map[string]any{"text": "token: " + secret})
	bad := body(t, map[string]any{"text": "token: " + secret, secret: 1})
	long := body(t, map[string]any{"text": strings.Repeat("a ", maxText/2)[:maxText-10] + " pin: 4821"})
	old := func(b []byte, d time.Duration) *http.Request { return signed(key, b, now.Add(d)) }
	unsigned := func(h, v string) *http.Request { r := old(good, 0); r.Header.Set(h, v); return r }
	const limit = 80 << 10
	big := []byte(strings.Repeat(" ", limit+1))
	broken := httptest.NewRequest(http.MethodPost, "/ingest/laptop", io.NopCloser(failing{}))
	dbErr := func(code string) error { return &pgconn.PgError{Code: code, Message: "x"} }
	for _, c := range []struct {
		name   string
		r      *http.Request
		bucket int
		isNew  bool
		err    error
		code   int
		reason string
		answer answer
	}{
		{"accepted", old(good, 0), 1, true, nil, 202, "", answer{PostID: postID, New: true, Masked: []string{"text"}}},
		{"a retry", old(good, 0), 1, false, nil, 202, "", answer{PostID: postID, Masked: []string{"text"}}},
		{"nothing masked", old(body(t, nil), 0), 1, true, nil, 202, "", answer{PostID: postID, New: true}},
		{"at the cap", old(append(slices.Clone(good), big[:limit-len(good)]...), 0), 1, true, nil, 202, "", answer{PostID: postID, New: true, Masked: []string{"text"}}},
		{"five minutes late", old(good, -skew), 1, true, nil, 202, "", answer{PostID: postID, New: true, Masked: []string{"text"}}},
		{"five minutes early", old(good, skew), 1, true, nil, 202, "", answer{PostID: postID, New: true, Masked: []string{"text"}}},
		{"too large", old(big, 0), 1, true, nil, 413, "too_large", answer{Error: "Request Entity Too Large"}},
		{"unreadable", broken, 1, true, nil, 400, "unreadable", answer{Error: "Bad Request"}},
		{"no signature", unsigned(SignatureHeader, ""), 1, true, nil, 401, "bad_signature", answer{Error: "Unauthorized"}},
		{"another timestamp", unsigned(TimestampHeader, strconv.FormatInt(now.Unix()+1, 10)), 1, true, nil, 401, "bad_signature", answer{Error: "Unauthorized"}},
		{"another key", signed([]byte("k"), good, now), 1, true, nil, 401, "bad_signature", answer{Error: "Unauthorized"}},
		{"unsigned over the rate", signed([]byte("k"), good, now), 0, true, nil, 401, "bad_signature", answer{Error: "Unauthorized"}},
		{"late", old(good, -skew-time.Second), 1, true, nil, 401, "skew", answer{Error: "timestamp: more than 5 minutes from the server's clock"}},
		{"early", old(good, skew+time.Second), 1, true, nil, 401, "skew", answer{Error: "timestamp: more than 5 minutes from the server's clock"}},
		{"late over the rate", old(good, -skew-time.Second), 0, true, nil, 401, "skew", answer{Error: "timestamp: more than 5 minutes from the server's clock"}},
		{"over the rate", old(good, 0), 0, true, nil, 429, "rate", answer{Error: "Too Many Requests"}},
		{"invalid", old(bad, 0), 1, true, nil, 400, "invalid_body", answer{Error: "body: not a JSON object of the fields session, session_label, repo, branch, post_id, text, about, needs_you and corrects, each of its type"}},
		{"too long, masked", old(long, 0), 1, true, nil, 400, "invalid_body", answer{Error: "text: 4004 characters, the limit is 4000", Masked: []string{"text"}}},
		{"store refused", old(good, 0), 1, true, dbErr("22P05"), 400, "store_refused", answer{Error: "Bad Request", Masked: []string{"text"}}},
		{"store down", old(good, 0), 1, true, dbErr("57P01"), 503, "store_unavailable", answer{Error: "Service Unavailable"}},
	} {
		buf := logs(t)
		var stored []event.Event
		h := handler(key, repos, func(_ context.Context, e event.Event) (bool, error) {
			stored = append(stored, e)
			return c.isNew, c.err
		},
			func() time.Time { return now }, rate.NewLimiter(0, c.bucket))
		before := map[string]float64{}
		for _, r := range metrics.IngestReasons {
			before[r] = testutil.ToFloat64(metrics.IngestRefusedFor(metrics.IngestLaptop, r))
		}
		accepted := testutil.ToFloat64(metrics.EventsFor(metrics.IngestLaptop, PostCreated))
		for _, h := range []string{"Ce-Source", "Ce-Actor", "Ce-Actortrusted"} {
			c.r.Header.Set(h, "true")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.r)
		out := buf.String() + w.Body.String()
		var a answer
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil || w.Code != c.code || !reflect.DeepEqual(a, c.answer) {
			t.Errorf("%s: %d %+v (%v), want %d %+v", c.name, w.Code, a, err, c.code, c.answer)
		}
		for _, r := range metrics.IngestReasons {
			want := 0.0
			if r == c.reason {
				want = 1
			}
			if got := testutil.ToFloat64(metrics.IngestRefusedFor(metrics.IngestLaptop, r)) - before[r]; got != want {
				t.Errorf("%s: refused %s %v, want %v", c.name, r, got, want)
			}
		}
		wantEvents := 0.0
		if c.code == 202 {
			wantEvents = 1
		}
		if got := testutil.ToFloat64(metrics.EventsFor(metrics.IngestLaptop, PostCreated)) - accepted; got != wantEvents {
			t.Errorf("%s: events %v", c.name, got)
		}
		if c.code == 429 && w.Header().Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", c.name)
		}
		if (len(stored) == 1) != (c.code == 202 || c.err != nil) {
			t.Errorf("%s: %d stored", c.name, len(stored))
		}
		for _, e := range stored {
			if leak(secret[4:], string(e.Data)+e.ID+e.Subject, 5) != "" || string(e.Producer) != `{"kind":"route","name":"ingest-laptop"}` || e.Source != LaptopSource || e.ActorTrusted {
				t.Errorf("%s: %+v", c.name, e)
			}
		}
		if leak(secret[4:], out, 5) != "" || strings.Contains(out, string(key)) {
			t.Errorf("%s: the body is in a log line or the answer: %s", c.name, out)
		}
		if c.code == 202 != strings.Contains(buf.String(), "ingest: event") {
			t.Errorf("%s: logged %s", c.name, buf.String())
		}
	}
	got, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if leak(secret[4:], f.String(), 5) != "" {
			t.Errorf("the body is in %s", f.GetName())
		}
	}
}

func TestHeadersOnce(t *testing.T) {
	logs(t)
	key := []byte(fake(hexes, 64))
	h := handler(key, repos, func(context.Context, event.Event) (bool, error) { return true, nil }, func() time.Time { return now }, rate.NewLimiter(0, 9))
	for _, name := range []string{"", TimestampHeader, SignatureHeader} {
		r := signed(key, body(t, nil), now)
		want := http.StatusAccepted
		if name != "" {
			r.Header.Add(name, r.Header.Get(name))
			want = http.StatusUnauthorized
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s twice: %d, want %d", name, w.Code, want)
		}
	}
}

func TestKey(t *testing.T) {
	k := fake(hexes, 64)
	for s, want := range map[string]string{k: "", "": "it is unset", k + "\n": "it ends with a newline", " " + k: "it starts or ends with a space", k + " ": "it starts or ends with a space",
		k[:63]: "it is not 64 lowercase hex characters", k + "0": "it is not 64 lowercase hex characters", strings.ToUpper(k): "it is not 64 lowercase hex characters",
		strings.Repeat("z", 64): "it is not 64 lowercase hex characters", strings.Repeat("0", 64): "it is not random", strings.Repeat("0123", 16): "it is not random"} {
		if got := Key(s); got != want {
			t.Errorf("%q: %q, want %q", s, got, want)
		}
	}
}

// A request that is refused early allocates the same whatever its body holds.
func TestSignatureFirst(t *testing.T) {
	logs(t)
	h := handler([]byte(fake(hexes, 64)), repos, func(context.Context, event.Event) (bool, error) { return true, nil }, func() time.Time { return now }, rate.NewLimiter(0, 0))
	run := func(b []byte) float64 {
		return testing.AllocsPerRun(50, func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signed([]byte("k"), b, now))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	full := body(t, map[string]any{"text": strings.Repeat("\ufdfa", maxText)})
	if blank, got := run(bytes.Repeat([]byte(" "), len(full))), run(full); got > blank+5 {
		t.Errorf("%v allocations, %v for a blank body", got, blank)
	}
}

// While a post is worked on, another waits its turn, and no longer than its time.
func TestBusy(t *testing.T) {
	logs(t)
	key := []byte(fake(hexes, 64))
	h := handler(key, repos, func(context.Context, event.Event) (bool, error) { return true, nil }, func() time.Time { return now }, rate.NewLimiter(0, 9))
	masking <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signed(key, body(t, nil), now).WithContext(ctx))
	<-masking
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Errorf("status %d", w.Code)
	}
	masking <- struct{}{}
	start := time.Now()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signed(key, body(t, nil), now))
	<-masking
	if d := time.Since(start); w.Code != http.StatusServiceUnavailable || d > working+time.Second {
		t.Errorf("status %d after %v", w.Code, d)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signed(key, body(t, nil), now))
	if w.Code != http.StatusAccepted {
		t.Errorf("then: status %d", w.Code)
	}
}

// One post is masked at a time, and a post whose time is up is not stored as an empty one.
func TestMaskingHeld(t *testing.T) {
	b := body(t, map[string]any{"text": strings.Repeat("\ufdfa password: ", maxText/12)})
	done, held, polls := make(chan struct{}), 0, 0
	go func() {
		defer close(done)
		_, _, _ = Post(context.Background(), b, repos, now)
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			polls++
			if len(masking) == 1 {
				held++
			}
		}
	}
	if held*2 < polls {
		t.Error("the mask ran without holding masking")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 20 {
		if _, _, err := Post(ctx, body(t, nil), repos, now); !errors.Is(err, context.Canceled) {
			t.Fatalf("%v", err)
		}
	}
}

// A post with every field at its limit, every character escaped as JSON allows, fits the cap and is stored.
func TestLargestPost(t *testing.T) {
	logs(t)
	key, wide := []byte(fake(hexes, 64)), func(n int) string { return strings.Repeat("\U0001F600", n) }
	b := body(t, map[string]any{"session_label": wide(maxRawLabel), "repo": wide(maxName), "branch": wide(maxName), "text": wide(maxText),
		"about": slices.Repeat([]any{map[string]any{"repo": "o/r", "number": maxNumber}}, maxAbout), "needs_you": slices.Repeat([]string{wide(maxNeed)}, maxNeeds)})
	var esc strings.Builder
	for _, r := range string(b) {
		if r < 0x80 {
			esc.WriteRune(r)
		} else {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&esc, `\u%04x\u%04x`, hi, lo)
		}
	}
	h := handler(key, repos, func(context.Context, event.Event) (bool, error) { return true, nil }, func() time.Time { return now }, rate.NewLimiter(0, 1))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signed(key, []byte(esc.String()), now))
	t.Logf("%d bytes, cap %d", esc.Len(), maxBody)
	if w.Code != http.StatusAccepted || esc.Len() > maxBody || esc.Len() <= maxBody-(4<<10) {
		t.Errorf("%d bytes: %d %s", esc.Len(), w.Code, w.Body)
	}
}

// Twenty of the largest bodies at once, on 2 CPUs and a 100 MiB limit, add under 32 MiB of heap.
func TestHeap(t *testing.T) {
	logs(t)
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(100 << 20))
	key := []byte(fake(hexes, 64))
	h := handler(key, repos, func(context.Context, event.Event) (bool, error) { return true, nil }, func() time.Time { return now }, rate.NewLimiter(0, 1000))
	for _, unit := range []string{"\ufdfa", "a\u0301", "password: ", "a:b@", "%25", "&#65;", "x1\n", "| a1 ", "\"a1\" + ", "-----BEGIN PRIVATE KEY-----", "eyJabcdefgh.", "passwords:\n- "} {
		text := []rune(strings.Repeat(unit, maxText))[:maxText]
		need := string(text[:maxNeed])
		b := body(t, map[string]any{"text": string(text), "needs_you": slices.Repeat([]string{need}, 2)})
		if len(b) > maxBody {
			t.Fatalf("%q: %d bytes", unit, len(b))
		}
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		base, peak := m.HeapAlloc, m.HeapAlloc
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				case <-time.After(2 * time.Millisecond):
					runtime.ReadMemStats(&m)
					peak = max(peak, m.HeapAlloc)
				}
			}
		}()
		var wg sync.WaitGroup
		codes := make([]int, 20)
		for i := range codes {
			wg.Go(func() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, signed(key, b, now))
				codes[i] = w.Code
			})
		}
		wg.Wait()
		close(stop)
		<-done
		t.Logf("%q: %d KiB, %v", unit, (peak-base)>>10, codes)
		if peak-base > 32<<20 {
			t.Errorf("%q: %d MiB", unit, (peak-base)>>20)
		}
		for _, c := range codes {
			if c != http.StatusAccepted && c != http.StatusServiceUnavailable && c != http.StatusBadRequest {
				t.Errorf("%q: status %d", unit, c)
			}
		}
	}
}

// The bucket refuses what comes after its burst, and refills.
func TestBucket(t *testing.T) {
	key, at, n := []byte(fake(hexes, 64)), now, 0
	logs(t)
	h := handler(key, repos, func(context.Context, event.Event) (bool, error) { n++; return true, nil }, func() time.Time { return at }, rate.NewLimiter(rate.Every(6*time.Second), 3))
	send := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signed(key, body(t, nil), at))
		return w.Code
	}
	for i, want := range []int{202, 202, 202, 429, 429} {
		if got := send(); got != want {
			t.Errorf("request %d: %d, want %d", i, got, want)
		}
	}
	at = at.Add(6 * time.Second)
	if got := send(); got != 202 || n != 4 {
		t.Errorf("after the refill: %d, %d stored", got, n)
	}
	// The route's own bucket is bounded: 20 at once.
	l := Laptop(string(key), repos, func(context.Context, event.Event) (bool, error) { return true, nil })
	refused := 0
	for range 25 {
		w := httptest.NewRecorder()
		l.ServeHTTP(w, signed(key, []byte("{}"), time.Now()))
		if w.Code == 429 {
			refused++
		}
	}
	if refused < 4 {
		t.Errorf("%d of 25 refused", refused)
	}
}
