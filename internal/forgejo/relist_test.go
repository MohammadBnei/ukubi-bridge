package forgejo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// fakeLog is the store's (source, ce_id) dedup and the cursor table.
type fakeLog struct {
	events  []event.Event
	cursors map[string]time.Time
}

func (l *fakeLog) insert(_ context.Context, e event.Event) (bool, error) {
	if slices.ContainsFunc(l.events, func(o event.Event) bool { return o.Source == e.Source && o.ID == e.ID }) {
		return false, nil
	}
	l.events = append(l.events, e)
	return true, nil
}

func (l *fakeLog) cursor(_ context.Context, repo string) (time.Time, error) {
	return l.cursors[repo], nil
}
func (l *fakeLog) setCursor(_ context.Context, repo string, t time.Time) error {
	l.cursors[repo] = t
	return nil
}

const relistHead = "3f1c0a9e5b2d4c6a8e0f1b3d5c7a9e1f2b4d6c8a"

func login(name string) map[string]any { return map[string]any{"login": name} }

func pr(n int, author, state, created, updated string, closed, mergedBy any) map[string]any {
	return map[string]any{"number": n, "title": fmt.Sprintf("PR %d", n), "user": login(author), "state": state, "created_at": created, "updated_at": updated,
		"closed_at": closed, "merged_by": mergedBy,
		"head": map[string]any{"sha": relistHead, "repo": map[string]any{"full_name": "MohammadBnei/editable-blog"}}}
}

// fakeForgejo serves one repo: the fleet's PR 42 (opened, approved and
// commented on in the window), PR 7 (opened long ago, merged in the window,
// on the pulls list's second page), PR 3 (last updated before the window, so
// the listing stops there), issue 9 and a comment on it. The repo is
// configured in lower case: Forgejo answers it with its own spelling. edit,
// if set, changes the routes first; *since gets each since a list was asked for.
func fakeForgejo(t *testing.T, edit func(map[string]any), since *[]string) *httptest.Server {
	const repo = "/api/v1/repos/MohammadBnei/editable-blog"
	routes := map[string]any{
		"/api/v1/repos/mohammadbnei/editable-blog": map[string]any{"full_name": "MohammadBnei/editable-blog"},
		repo + "/pulls": []any{pr(42, "ukubi-fleet", "open", "2026-11-21T09:00:00Z", "2026-11-21T09:20:00Z", nil, nil)},
		repo + "/pulls?page=2": []any{
			pr(7, "MohammadBnei", "closed", "2026-10-01T09:00:00Z", "2026-11-21T09:15:00Z", "2026-11-21T09:15:00Z", login("MohammadBnei")),
			pr(3, "MohammadBnei", "closed", "2026-10-01T09:00:00Z", "2026-11-20T09:00:00Z", "2026-11-20T09:00:00Z", login("MohammadBnei")),
		},
		repo + "/pulls/42/reviews": []any{
			map[string]any{"user": login("ukubi-review"), "state": "APPROVED", "body": "LGTM", "commit_id": relistHead, "submitted_at": "2026-11-21T09:12:00Z"},
			map[string]any{"user": login("stranger"), "state": "PENDING", "body": "draft", "commit_id": relistHead, "submitted_at": "2026-11-21T09:13:00Z"},
			// An inline code comment: an empty COMMENT review, keyed by its id.
			map[string]any{"id": 77, "user": login("stranger"), "state": "COMMENT", "body": "", "commit_id": relistHead, "submitted_at": "2026-11-21T09:13:30Z"},
			// No reviewer and no id, so no key: skipped, never a stuck cursor.
			map[string]any{"user": nil, "state": "COMMENT", "body": "?", "commit_id": relistHead, "submitted_at": "2026-11-21T09:14:00Z"},
		},
		repo + "/pulls/7/reviews": []any{},
		repo + "/issues":          []any{map[string]any{"number": 9, "title": "Issue 9", "user": login("stranger"), "created_at": "2026-11-21T08:00:00Z"}},
		repo + "/issues/comments": []any{
			// A trusted login's comment, edited since (by anyone with write access).
			map[string]any{"id": 901, "user": login("MohammadBnei"), "body": "edited", "pull_request_url": "https://git.bnei.dev/MohammadBnei/editable-blog/pulls/42",
				"issue_url": "", "created_at": "2026-11-21T09:10:00Z", "updated_at": "2026-11-21T09:30:00Z"},
			map[string]any{"id": 902, "user": login("stranger"), "pull_request_url": "",
				"issue_url": "https://git.bnei.dev/MohammadBnei/editable-blog/issues/9", "created_at": "2026-11-21T08:30:00Z"},
		},
	}
	if edit != nil {
		edit(routes)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := r.URL.Query().Get("since"); s != "" && since != nil {
			*since = append(*since, s)
		}
		if r.Header.Get("Authorization") != "token secret" {
			t.Errorf("%s: authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		key := r.URL.Path
		if p := r.URL.Query().Get("page"); p != "" {
			key += "?page=" + p
		}
		if r.URL.Path == repo+"/pulls" && key == r.URL.Path {
			// ROOT_URL's host, not the one the bridge reaches: the next page still goes to r.API.
			w.Header().Set("Link", fmt.Sprintf(`<https://forgejo.invalid%s?page=2>; rel="next"`, repo+"/pulls"))
		}
		body, ok := routes[key]
		if !ok {
			t.Errorf("unexpected GET %s", r.URL)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func relister(t *testing.T, srv *httptest.Server, log *fakeLog) *Relister {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Relister{API: srv.URL, TokenFile: tok, Repos: []string{"mohammadbnei/editable-blog"}, Policy: policy,
		MaxAge: 720 * time.Hour, Insert: log.insert, Cursor: log.cursor, SetCursor: log.setCursor, Client: srv.Client()}
}

func TestRelist(t *testing.T) {
	var since []string
	srv := fakeForgejo(t, nil, &since)
	log := &fakeLog{cursors: map[string]time.Time{}}
	r := relister(t, srv, log)
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	// The webhook got PR 42's opened earlier: the relisted copy is the same event.
	webhook, err := Normalize(policy, "pull_request", "delivery-1", fixture(t, "pull_request_opened"), now)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = log.insert(context.Background(), webhook)

	n, err := r.Run(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id, typ, login string
		trusted, owned bool
	}
	var got []row
	for _, e := range log.events[1:] {
		got = append(got, row{e.ID, e.Type, e.ActorLogin, e.ActorTrusted, e.ThreadOwned})
		if e.Source != webhook.Source {
			t.Errorf("%s: source %s", e.ID, e.Source)
		}
	}
	// Oldest first. PR 7's opened is older than the window, PR 3 is not listed,
	// the PENDING review is a draft, the reviewer-less one has no key. No
	// relisted fact is actor_trusted, not even the trusted login's (edited)
	// comment or merge.
	want := []row{
		{"issue/9/opened", "dev.bnei.forge.issues.opened", "stranger", false, false},
		{"comment/902", "dev.bnei.forge.issue_comment.created", "stranger", false, false},
		{"comment/901", "dev.bnei.forge.issue_comment.created", "MohammadBnei", false, true},
		{"pr/42/review/approved/ukubi-review/" + relistHead + "/" + textSum("LGTM"), "dev.bnei.forge.pull_request_review.approved", "ukubi-review", false, true},
		{"pr/42/review/comment/77", "dev.bnei.forge.pull_request_review.comment", "stranger", false, true},
		{"pr/7/closed/1795252500", "dev.bnei.forge.pull_request.closed", "MohammadBnei", false, true},
	}
	if n != len(want) || !slices.Equal(got, want) {
		t.Fatalf("inserted %d:\n%v\nwant\n%v", n, got, want)
	}
	// A relisted comment's issue is the thread's object, as in the webhook's.
	for _, e := range log.events[2:4] {
		var d struct {
			Issue struct{ Title string } `json:"issue"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil || d.Issue.Title == "" {
			t.Errorf("%s: issue without its title: %s", e.ID, e.Data)
		}
	}
	// The relisted copies carry the same keys as their webhook deliveries.
	for _, c := range []struct{ fixture, kind, id string }{
		{"pull_request_comment_created", "pull_request_comment", "comment/901"},
		{"pull_request_review_approved", "pull_request_review_approved", want[3].id},
	} {
		if e, err := Normalize(policy, c.kind, "delivery-2", fixture(t, c.fixture), now); err != nil || e.ID != c.id {
			t.Errorf("%s: webhook id %q (%v), relisted %q", c.fixture, e.ID, err, c.id)
		}
	}
	if !log.cursors["mohammadbnei/editable-blog"].Equal(now) {
		t.Errorf("cursor %v", log.cursors)
	}
	// A first run looks back 6h, plus the overlap, on both since lists.
	if first := "2026-11-21T03:55:00Z"; !slices.Equal(since, []string{first, first}) {
		t.Errorf("since %v, want %s twice", since, first)
	}

	// Idempotent: the same window relisted again (a lost cursor) lists every
	// fact again, and the (source, ce_id) dedup drops each one.
	delete(log.cursors, "mohammadbnei/editable-blog")
	if n, err := r.Run(context.Background(), now); err != nil || n != 0 {
		t.Errorf("second run: %d %v", n, err)
	}
}

// A repo whose listing fails keeps its cursor; the run reports it.
func TestRelistFailureKeepsCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("secret"), 0o600)
	before := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	log := &fakeLog{cursors: map[string]time.Time{"a/b": before}}
	r := &Relister{API: srv.URL, TokenFile: tok, Repos: []string{"a/b"}, Policy: policy, MaxAge: time.Hour,
		Insert: log.insert, Cursor: log.cursor, SetCursor: log.setCursor, Client: srv.Client()}
	if _, err := r.Run(context.Background(), before.Add(time.Hour)); err == nil {
		t.Fatal("a failed listing is an error")
	}
	if !log.cursors["a/b"].Equal(before) {
		t.Errorf("cursor moved to %v", log.cursors["a/b"])
	}
}

// A later window starts the overlap before the cursor, never further back
// than MaxAge.
func TestRelistWindow(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name   string
		cursor time.Time
		maxAge time.Duration
		want   string
	}{
		{"cursor", now.Add(-10 * time.Minute), 720 * time.Hour, "2026-11-21T09:45:00Z"},
		{"clamped", now.Add(-3 * time.Hour), time.Hour, "2026-11-21T09:00:00Z"},
	} {
		var since []string
		srv := fakeForgejo(t, nil, &since)
		log := &fakeLog{cursors: map[string]time.Time{"mohammadbnei/editable-blog": c.cursor}}
		r := relister(t, srv, log)
		r.MaxAge = c.maxAge
		if _, err := r.Run(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(since, []string{c.want, c.want}) {
			t.Errorf("%s: since %v, want %s", c.name, since, c.want)
		}
	}
}

// A run whose pulls list shifted under it (a page repeats a PR) may have
// skipped one, and a run whose Insert failed did not finish: both keep the
// cursor, so the next run covers the same window.
func TestRelistKeepsCursor(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	before := now.Add(-2 * time.Hour) // the window holds every fact
	const repo = "/api/v1/repos/MohammadBnei/editable-blog"
	shifted := func(routes map[string]any) {
		routes[repo+"/pulls?page=2"] = append([]any{routes[repo+"/pulls"].([]any)[0]}, routes[repo+"/pulls?page=2"].([]any)...)
	}
	for _, c := range []struct {
		name   string
		edit   func(map[string]any)
		insert func(*fakeLog) func(context.Context, event.Event) (bool, error)
	}{
		{"shifted", shifted, func(l *fakeLog) func(context.Context, event.Event) (bool, error) { return l.insert }},
		{"insert failed", nil, func(*fakeLog) func(context.Context, event.Event) (bool, error) {
			return func(context.Context, event.Event) (bool, error) { return false, errors.New("store down") }
		}},
	} {
		srv := fakeForgejo(t, c.edit, nil)
		log := &fakeLog{cursors: map[string]time.Time{"mohammadbnei/editable-blog": before}}
		r := relister(t, srv, log)
		r.Insert = c.insert(log)
		_, _ = r.Run(context.Background(), now)
		if got := log.cursors["mohammadbnei/editable-blog"]; !got.Equal(before) {
			t.Errorf("%s: cursor moved to %v", c.name, got)
		}
	}
}
