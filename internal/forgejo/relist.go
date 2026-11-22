package forgejo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
	"github.com/MohammadBnei/ukubi-bridge/internal/metrics"
)

// Relisting is how a Forgejo delivery lost to bridge downtime or a 503 comes
// back: Forgejo neither retries nor lists its deliveries. Each run lists, per
// watched repo, the PRs, issues, comments and reviews changed since the repo's
// cursor, and inserts the facts in them (factID) that happened since, oldest
// first. The log's (source, ce_id) dedup drops the ones it holds already.
//
// A relisted fact is never actor_trusted: it carries the object as it is now,
// and any collaborator (a fleet agent too) can edit another user's comment or
// PR/issue body, so the author's trust would vouch for text they may not have
// written. The webhook's copy, built from the original payload, keeps it.
// thread_owned stays: a thread's author is not editable.
const (
	// firstLookback is how far back a repo's first run looks.
	firstLookback = 6 * time.Hour
	// overlap widens each window for clock skew between the bridge and Forgejo;
	// what it lists twice is a duplicate.
	overlap = 5 * time.Minute
)

// Relister relists the Repos' facts into the log.
type Relister struct {
	API string // "https://git.bnei.dev"
	// TokenFile holds a Forgejo token with read:repository and read:issue
	// only. It is read on every run, so a rotation needs no restart.
	TokenFile string
	Repos     []string // owner/repo
	Policy    github.Policy
	// MaxAge bounds how far back a run looks, whatever the cursor says: a fact
	// older than retention may have had its event deleted, and would be new again.
	MaxAge time.Duration
	Insert func(ctx context.Context, e event.Event) (bool, error) // store.Insert
	// Cursor is where repo's last good run started, zero if it never ran;
	// SetCursor stores it (store.RelistCursor, store.SetRelistCursor).
	Cursor    func(ctx context.Context, repo string) (time.Time, error)
	SetCursor func(ctx context.Context, repo string, t time.Time) error
	Client    *http.Client
}

// The parts of Forgejo's API objects the loop reads. Each one is also kept raw
// and put in the event's data, in the place a webhook payload has it.
type apiPull struct {
	Number    int             `json:"number"`
	User      json.RawMessage `json:"user"`
	State     string          `json:"state"`
	MergedBy  json.RawMessage `json:"merged_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	ClosedAt  *time.Time      `json:"closed_at"`
}

type apiIssue struct {
	Number    int             `json:"number"`
	User      json.RawMessage `json:"user"`
	CreatedAt time.Time       `json:"created_at"`
}

type apiRepo struct {
	FullName string `json:"full_name"`
}

type apiComment struct {
	ID        int64           `json:"id"`
	User      json.RawMessage `json:"user"`
	PRURL     string          `json:"pull_request_url"` // set on a PR's comment
	IssueURL  string          `json:"issue_url"`        // set on an issue's
	CreatedAt time.Time       `json:"created_at"`
}

type apiReview struct {
	ID          int64           `json:"id"`
	User        json.RawMessage `json:"user"`
	State       string          `json:"state"`
	Body        string          `json:"body"`
	CommitID    string          `json:"commit_id"`
	SubmittedAt time.Time       `json:"submitted_at"`
}

// reviewKinds maps a review's state to its webhook event type; PENDING (a
// draft) and REQUEST_REVIEW are not reviews yet.
var reviewKinds = map[string]string{
	"APPROVED":        "pull_request_review_approved",
	"REQUEST_CHANGES": "pull_request_review_rejected",
	"COMMENT":         "pull_request_review_comment",
}

// fact is one webhook-shaped payload rebuilt from the API, and when it happened.
type fact struct {
	kind string
	at   time.Time
	body map[string]any
}

var nextPage = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Run relists every repo once. A repo that fails keeps its cursor, so its next
// run covers the same window again; the others go on.
func (r *Relister) Run(ctx context.Context, now time.Time) (int, error) {
	raw, err := os.ReadFile(r.TokenFile)
	if err != nil {
		metrics.SetEnabled(metrics.ForgejoRelist, false) // the missing token file; Loop logs the error
		return 0, err
	}
	metrics.SetEnabled(metrics.ForgejoRelist, true)
	token := strings.TrimSpace(string(raw))
	n := 0
	var errs []error
	for _, repo := range r.Repos {
		k, err := r.relist(ctx, token, repo, now)
		n += k
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", repo, err))
		}
	}
	return n, errors.Join(errs...)
}

func (r *Relister) relist(ctx context.Context, token, repo string, now time.Time) (int, error) {
	since, err := r.Cursor(ctx, repo)
	if err != nil {
		return 0, err
	}
	if since.IsZero() {
		since = now.Add(-firstLookback)
	}
	since = since.Add(-overlap)
	if oldest := now.Add(-r.MaxAge); since.Before(oldest) {
		since = oldest
	}
	base := r.API + "/api/v1/repos/" + repo
	// Forgejo's own spelling, as the webhook's repository.full_name has it: the
	// API matches owner/repo in any case, the event's source and subject do not.
	var meta apiRepo
	if _, err := r.get(ctx, token, base, &meta); err != nil {
		return 0, err
	}
	if meta.FullName == "" {
		return 0, errors.New("repository without full_name")
	}
	base = r.API + "/api/v1/repos/" + meta.FullName
	sinceQ := url.QueryEscape(since.UTC().Format(time.RFC3339))
	var facts []fact
	add := func(kind string, at time.Time, body map[string]any) {
		if !at.Before(since) {
			body["repository"] = map[string]string{"full_name": meta.FullName}
			body["relisted"] = true
			facts = append(facts, fact{kind, at, body})
		}
	}

	// The pulls list has no since: newest update first, until one is older.
	// ponytail: a comment or a review bumps its PR's updated_at (Forgejo's
	// updateCommentInfos), so the PRs listed here cover every review since.
	pulls := map[int]json.RawMessage{}
	// A PR updated while its pages are listed jumps to page 1 and shifts the
	// rest down a place: a later page then repeats one already seen, and the
	// PR it pushed past is skipped. Such a run keeps the cursor, so the next
	// covers this window again.
	// ponytail: a PR opened mid-listing reads as a shift too; it only costs a
	// window listed twice.
	drift := false
	// The PR or issue object, by number: a relisted comment's issue. A PR's
	// is its PR object (number, user, title, body, html_url, state), not
	// the webhook's issue view of it.
	threads := map[int]json.RawMessage{}
	err = r.pages(ctx, token, base+"/pulls?state=all&sort=recentupdate&limit=50", func(raw json.RawMessage) (bool, error) {
		var p apiPull
		if err := json.Unmarshal(raw, &p); err != nil {
			return false, err
		}
		if p.UpdatedAt.Before(since) {
			return false, nil
		}
		if _, seen := pulls[p.Number]; seen {
			drift = true
			return true, nil
		}
		pulls[p.Number], threads[p.Number] = raw, raw
		add("pull_request", p.CreatedAt, map[string]any{"action": "opened", "number": p.Number, "pull_request": raw, "sender": p.User})
		if p.State == "closed" && p.ClosedAt != nil {
			// Who closed it is known only for a merge: an unmerged close has no
			// sender, so its actor is empty.
			add("pull_request", *p.ClosedAt, map[string]any{"action": "closed", "number": p.Number, "pull_request": raw, "sender": p.MergedBy})
		}
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	for num, raw := range pulls {
		err := r.pages(ctx, token, fmt.Sprintf("%s/pulls/%d/reviews?limit=50", base, num), func(rr json.RawMessage) (bool, error) {
			var v apiReview
			if err := json.Unmarshal(rr, &v); err != nil {
				return false, err
			}
			if kind := reviewKinds[v.State]; kind != "" {
				add(kind, v.SubmittedAt, map[string]any{"action": "reviewed", "number": num, "pull_request": raw,
					"sender": v.User, "commit_id": v.CommitID, "review": map[string]any{"id": v.ID, "type": kind, "content": v.Body}})
			}
			return true, nil
		})
		if err != nil {
			return 0, err
		}
	}
	err = r.pages(ctx, token, base+"/issues?type=issues&state=all&limit=50&since="+sinceQ, func(raw json.RawMessage) (bool, error) {
		var i apiIssue
		if err := json.Unmarshal(raw, &i); err != nil {
			return false, err
		}
		threads[i.Number] = raw
		add("issues", i.CreatedAt, map[string]any{"action": "opened", "issue": raw, "sender": i.User})
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	// Comments on issues and PRs alike (the webhook's issue_comment).
	err = r.pages(ctx, token, base+"/issues/comments?limit=50&since="+sinceQ, func(raw json.RawMessage) (bool, error) {
		var c apiComment
		if err := json.Unmarshal(raw, &c); err != nil {
			return false, err
		}
		thread, isPull := c.IssueURL, c.PRURL != ""
		if isPull {
			thread = c.PRURL
		}
		num, err := strconv.Atoi(path.Base(thread))
		issue, ok := threads[num]
		if err != nil || !ok {
			// Its thread was updated with it, so it is listed above unless the
			// comment is older than the window or its URL is not a thread's.
			if !c.CreatedAt.Before(since) {
				slog.Warn("forgejo relist: comment without its thread", "repo", repo, "comment", c.ID, "thread", thread)
			}
			return true, nil
		}
		body := map[string]any{"action": "created", "is_pull": isPull, "comment": raw, "sender": c.User,
			"issue": issue}
		if isPull {
			body["pull_request"] = pulls[num] // the fork rule reads its head
		}
		add("issue_comment", c.CreatedAt, body)
		return true, nil
	})
	if err != nil {
		return 0, err
	}

	// Oldest first, so a missed opened lands before its closed.
	slices.SortStableFunc(facts, func(a, b fact) int { return a.at.Compare(b.at) })
	n := 0
	for _, f := range facts {
		body, err := json.Marshal(f.body)
		if err != nil {
			return n, err
		}
		e, err := Normalize(r.Policy, f.kind, "", body, f.at)
		if err != nil {
			// Refused now, refused on every run: failing the repo would pin its
			// cursor for good (e.g. a review without its reviewer has no key).
			slog.Warn("forgejo relist: fact skipped", "repo", repo, "kind", f.kind, "at", f.at, "err", err)
			continue
		}
		e.ActorTrusted = false // see the top of this file
		e.Producer = event.Producer("route", "forgejo-relist")
		inserted, err := r.Insert(ctx, e)
		if err != nil {
			return n, err
		}
		if inserted {
			metrics.Event(metrics.ForgejoRelist, e.Type)
			slog.Info("forgejo relist: event", "type", e.Type, "subject", e.Subject, "id", e.ID)
			n++
		}
	}
	if drift {
		slog.Info("forgejo relist: the pulls list shifted while paged; cursor kept", "repo", repo)
		return n, nil
	}
	return n, r.SetCursor(ctx, repo, now)
}

// get GETs u into v and returns the response's headers.
func (r *Relister) get(ctx context.Context, token, u string, v any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(resp.Body).Decode(v)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || err != nil {
		return nil, fmt.Errorf("GET %s: status %d: %v", req.URL.Path, resp.StatusCode, err)
	}
	return resp.Header, nil
}

// pages GETs next and each next page its Link header names, handing every item
// to each until it returns false. Forgejo builds Link from its ROOT_URL, which
// is not r.API when the bridge reaches Forgejo by an internal URL: the next
// page's path and query go to r.API's scheme and host, so the token never
// leaves it.
func (r *Relister) pages(ctx context.Context, token, next string, each func(json.RawMessage) (bool, error)) error {
	api, err := url.Parse(r.API)
	if err != nil {
		return err
	}
	for next != "" {
		var page []json.RawMessage
		h, err := r.get(ctx, token, next, &page)
		if err != nil {
			return err
		}
		next = ""
		if m := nextPage.FindStringSubmatch(h.Get("Link")); m != nil {
			u, err := url.Parse(m[1])
			if err != nil {
				return fmt.Errorf("the Link header's next %q: %w", m[1], err)
			}
			u.Scheme, u.Host, u.User = api.Scheme, api.Host, nil
			next = u.String()
		}
		for _, item := range page {
			more, err := each(item)
			if err != nil {
				return err
			}
			if !more {
				return nil
			}
		}
	}
	return nil
}

// Loop runs every interval until ctx ends, starting now.
func (r *Relister) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, err := r.Run(ctx, time.Now())
		metrics.RelistRun(err)
		if err != nil {
			slog.Error("forgejo relist", "inserted", n, "err", err)
		} else if n > 0 {
			slog.Info("forgejo relist done", "inserted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
