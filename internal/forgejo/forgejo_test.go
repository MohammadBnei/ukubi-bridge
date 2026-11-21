package forgejo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
)

var policy = github.Policy{
	Trusted: map[string]bool{"MohammadBnei": true},
	Agents:  map[string]bool{"ukubi-fleet": true, "ukubi-review": true},
}

func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify(t *testing.T) {
	body := fixture(t, "pull_request_opened")
	if !Verify([]byte("s"), body, sign("s", body)) {
		t.Fatal("valid signature rejected")
	}
	for name, h := range map[string]string{
		"empty (webhook without secret)": "",
		"not hex":                        "zz",
		"other secret":                   sign("other", body),
		"github form":                    "sha256=" + sign("s", body),
		"truncated":                      sign("s", body)[:32],
		"other body":                     sign("s", append([]byte(" "), body...)),
	} {
		if Verify([]byte("s"), body, h) {
			t.Errorf("%s: bad signature accepted", name)
		}
	}
}

// One row per carried event type, on the fixture of that delivery; the trust
// rules are github.Normalize's (the operator is trusted; ukubi-fleet and
// ukubi-review are agents, never trusted, and their threads are owned).
func TestNormalize(t *testing.T) {
	const home = "forge/MohammadBnei/editable-blog/"
	cases := []struct {
		fixture, kind     string
		typ, subject      string
		login, actorKind  string
		actor, threadOwns bool
	}{
		// opened is the author's action: the fleet's PR, owned, never trusted.
		{"pull_request_opened", "pull_request", "pull_request.opened", "pr/42", "ukubi-fleet", event.ActorAgent, false, true},
		// A fork is never owned, whoever opened it.
		{"pull_request_opened_fork", "pull_request", "pull_request.opened", "pr/42", "MohammadBnei", event.ActorHuman, true, false},
		// A deleted fork (head.repo null) is a fork too.
		{"pull_request_opened_deleted_fork", "pull_request", "pull_request.opened", "pr/42", "MohammadBnei", event.ActorHuman, true, false},
		// synchronized, closed, reopened and label_updated are the sender's.
		{"pull_request_synchronized", "pull_request_sync", "pull_request.synchronized", "pr/42", "MohammadBnei", event.ActorHuman, true, true},
		{"pull_request_closed", "pull_request", "pull_request.closed", "pr/42", "stranger", event.ActorHuman, false, true},
		{"pull_request_reopened", "pull_request", "pull_request.reopened", "pr/42", "MohammadBnei", event.ActorHuman, true, true},
		{"pull_request_label_updated", "pull_request_label", "pull_request.label_updated", "pr/42", "MohammadBnei", event.ActorHuman, true, false},
		{"issues_opened", "issues", "issues.opened", "issue/9", "stranger", event.ActorHuman, false, false},
		// The owner labelling a stranger's issue does not adopt it.
		{"issues_label_updated", "issue_label", "issues.label_updated", "issue/9", "MohammadBnei", event.ActorHuman, true, false},
		{"issue_comment_created", "issue_comment", "issue_comment.created", "issue/9", "stranger", event.ActorHuman, false, true},
		// The operator steering a fleet PR stays trusted.
		{"pull_request_comment_created", "pull_request_comment", "issue_comment.created", "pr/42", "MohammadBnei", event.ActorHuman, true, true},
		// The PR is in a comment's payload: a comment on a fork PR is not owned.
		{"pull_request_comment_fork", "pull_request_comment", "issue_comment.created", "pr/42", "MohammadBnei", event.ActorHuman, true, false},
		// A PR comment whose PR Forgejo could not build is not owned: fail closed.
		{"pull_request_comment_no_pr", "pull_request_comment", "issue_comment.created", "pr/42", "MohammadBnei", event.ActorHuman, true, false},
		// The reviewer is the sender. The fleet reviewer's approval is an agent's.
		{"pull_request_review_approved", "pull_request_review_approved", "pull_request_review.approved", "pr/42", "ukubi-review", event.ActorAgent, false, true},
		{"pull_request_review_rejected", "pull_request_review_rejected", "pull_request_review.rejected", "pr/42", "MohammadBnei", event.ActorHuman, true, true},
		{"pull_request_review_comment", "pull_request_review_comment", "pull_request_review.comment", "pr/42", "stranger", event.ActorHuman, false, true},
		// A run is owned by whoever triggered it.
		{"action_run_failure", "action_run_failure", "action_run.failure", "run/117", "ukubi-fleet", event.ActorAgent, false, true},
		{"action_run_success", "action_run_success", "action_run.success", "run/117", "MohammadBnei", event.ActorHuman, true, true},
		{"action_run_recover", "action_run_recover", "action_run.recover", "run/117", "MohammadBnei", event.ActorHuman, true, true},
		{"action_run_failure_fork", "action_run_failure", "action_run.failure", "run/117", "MohammadBnei", event.ActorHuman, true, false},
	}
	for _, c := range cases {
		e, err := Normalize(policy, c.kind, "8a0f7c1e-5d2b-4e3a-9c6f-1b2d3e4f5a6b", fixture(t, c.fixture), time.Unix(0, 0))
		if err != nil {
			t.Errorf("%s: %v", c.fixture, err)
			continue
		}
		if e.ID != "8a0f7c1e-5d2b-4e3a-9c6f-1b2d3e4f5a6b" || e.Source != "git.bnei.dev/MohammadBnei/editable-blog" ||
			e.Type != "dev.bnei.forge."+c.typ || e.Subject != home+c.subject {
			t.Errorf("%s: envelope id=%s source=%s type=%s subject=%s", c.fixture, e.ID, e.Source, e.Type, e.Subject)
		}
		if e.ActorLogin != c.login || e.Actor != c.actorKind || e.ActorTrusted != c.actor || e.ThreadOwned != c.threadOwns {
			t.Errorf("%s: actor=%s/%s actorTrusted=%v threadOwned=%v, want %s/%s %v %v", c.fixture,
				e.ActorLogin, e.Actor, e.ActorTrusted, e.ThreadOwned, c.login, c.actorKind, c.actor, c.threadOwns)
		}
	}
}

func TestNormalizeIgnored(t *testing.T) {
	for _, c := range []struct{ fixture, kind string }{
		{"push", "push"},
		// A carried payload under an event type that is not carried.
		{"pull_request_opened", "pull_request_assign"},
		{"pull_request_review_approved", "pull_request_review_request"},
		// An action the type does not carry: a PR's opened sent as a label change.
		{"pull_request_opened", "pull_request_label"},
	} {
		if _, err := Normalize(policy, c.kind, "d", fixture(t, c.fixture), time.Unix(0, 0)); !errors.Is(err, ErrIgnored) {
			t.Errorf("%s as %s: err=%v, want ErrIgnored", c.fixture, c.kind, err)
		}
	}
	if _, err := Normalize(policy, "pull_request", "", fixture(t, "pull_request_opened"), time.Unix(0, 0)); err == nil || errors.Is(err, ErrIgnored) {
		t.Errorf("no delivery id: err=%v, want a refusal", err)
	}
}
