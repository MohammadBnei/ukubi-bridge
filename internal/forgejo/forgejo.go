// Package forgejo turns Forgejo webhook deliveries (Gitea-compatible
// payloads, the "Forgejo" webhook type) into bus events.
package forgejo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
)

// Verify checks X-Forgejo-Signature against the webhook secret: the hex
// HMAC-SHA256 of the raw body, with no "sha256=" prefix. Forgejo sends an
// empty signature when the webhook has no secret, which never verifies.
func Verify(secret, body []byte, header string) bool {
	got, err := hex.DecodeString(header)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

// allowed lists the accepted X-Forgejo-Event-Type / payload action pairs. The
// specific type, not X-Forgejo-Event: Forgejo sends a review as its own event
// (pull_request_approved, pull_request_rejected, and pull_request_comment for
// a comment review, which is not a PR comment), and a PR comment as
// issue_comment. push and commit statuses fan out per commit (ADR-0060 §5).
var allowed = map[string]map[string]bool{
	"pull_request":                 {"opened": true, "closed": true, "reopened": true},
	"pull_request_sync":            {"synchronized": true},
	"pull_request_label":           {"label_updated": true},
	"issues":                       {"opened": true},
	"issue_label":                  {"label_updated": true},
	"issue_comment":                {"created": true},
	"pull_request_comment":         {"created": true},
	"pull_request_review_approved": {"reviewed": true},
	"pull_request_review_rejected": {"reviewed": true},
	"pull_request_review_comment":  {"reviewed": true},
	"action_run_success":           {"success": true},
	"action_run_failure":           {"failure": true},
	"action_run_recover":           {"recover": true},
}

// ErrIgnored means the delivery is valid but not an event the bus carries.
var ErrIgnored = errors.New("event type not carried")

type user struct {
	Login string `json:"login"`
}

type repo struct {
	FullName string `json:"full_name"`
}

type pull struct {
	Number int  `json:"number"`
	User   user `json:"user"`
	Head   struct {
		Repo *repo `json:"repo"` // nil when the fork was deleted
	} `json:"head"`
}

type payload struct {
	Action      string `json:"action"`
	Sender      user   `json:"sender"`
	Repository  repo   `json:"repository"`
	PullRequest *pull  `json:"pull_request"` // also on a PR comment
	Issue       *struct {
		Number int  `json:"number"`
		User   user `json:"user"`
	} `json:"issue"`
	IsPull  bool `json:"is_pull"`
	Comment *struct {
		User user `json:"user"`
	} `json:"comment"`
	// An action_run_* payload has no repository or sender at the top level.
	Run *struct {
		Index             int  `json:"index_in_repo"`
		Repository        repo `json:"repository"`
		TriggerUser       user `json:"trigger_user"`
		IsForkPullRequest bool `json:"is_fork_pull_request"`
	} `json:"run"`
}

// Normalize builds the bus event for one delivery. kind is
// X-Forgejo-Event-Type, delivery is X-Forgejo-Delivery. The bus type is
// dev.bnei.forge.<event>.<action>, where a review is
// pull_request_review.approved|rejected|comment and a run is
// action_run.success|failure|recover.
func Normalize(p github.Policy, kind, delivery string, body []byte, now time.Time) (event.Event, error) {
	var pl payload
	if err := json.Unmarshal(body, &pl); err != nil {
		return event.Event{}, fmt.Errorf("decode %s: %w", kind, err)
	}
	if !allowed[kind][pl.Action] {
		return event.Event{}, ErrIgnored
	}
	if pl.Run != nil {
		pl.Repository = pl.Run.Repository
	}
	if pl.Repository.FullName == "" || delivery == "" {
		return event.Event{}, errors.New("missing repository or delivery id")
	}

	// The actor and author rules are github.Normalize's: opened is the
	// author's, every other action the sender's.
	var actor, author user
	var name, action, subject string
	switch kind {
	case "pull_request", "pull_request_sync", "pull_request_label":
		if pl.PullRequest == nil {
			return event.Event{}, errors.New("pull_request event without pull_request")
		}
		actor, author = pl.PullRequest.User, pl.PullRequest.User
		if pl.Action != "opened" {
			actor = pl.Sender
		}
		name, action = "pull_request", pl.Action
		subject = fmt.Sprintf("forge/%s/pr/%d", pl.Repository.FullName, pl.PullRequest.Number)
	case "issues", "issue_label":
		if pl.Issue == nil {
			return event.Event{}, errors.New("issues event without issue")
		}
		actor, author = pl.Issue.User, pl.Issue.User
		if pl.Action != "opened" {
			actor = pl.Sender
		}
		name, action = "issues", pl.Action
		subject = fmt.Sprintf("forge/%s/issue/%d", pl.Repository.FullName, pl.Issue.Number)
	case "issue_comment", "pull_request_comment":
		if pl.Issue == nil || pl.Comment == nil {
			return event.Event{}, errors.New("issue_comment without issue or comment")
		}
		actor, author = pl.Comment.User, pl.Issue.User
		thread := "issue"
		if pl.IsPull {
			thread = "pr"
		}
		name, action = "issue_comment", pl.Action
		subject = fmt.Sprintf("forge/%s/%s/%d", pl.Repository.FullName, thread, pl.Issue.Number)
	case "pull_request_review_approved", "pull_request_review_rejected", "pull_request_review_comment":
		if pl.PullRequest == nil {
			return event.Event{}, errors.New("pull_request review without pull_request")
		}
		// The review carries no user: the sender is the reviewer.
		actor, author = pl.Sender, pl.PullRequest.User
		name, action = "pull_request_review", strings.TrimPrefix(kind, "pull_request_review_")
		subject = fmt.Sprintf("forge/%s/pr/%d", pl.Repository.FullName, pl.PullRequest.Number)
	default: // action_run_*
		if pl.Run == nil {
			return event.Event{}, errors.New("action_run event without run")
		}
		// A run is its own thread, owned by whoever triggered it: the pusher,
		// or the PR's author or syncer. index_in_repo, not the instance-wide
		// id: it is the run's number in its URL (/actions/runs/<index>).
		actor, author = pl.Run.TriggerUser, pl.Run.TriggerUser
		name, action = "action_run", pl.Action
		subject = fmt.Sprintf("forge/%s/run/%d", pl.Repository.FullName, pl.Run.Index)
	}

	// Two facts, never one bit (agent-fleet ADR-0082 §12), as in
	// github.Normalize. An empty login (no sender) is never trusted.
	actorTrusted := p.Trusted[actor.Login]
	threadOwned := p.Trusted[author.Login] || p.Agents[author.Login]
	// A PR from a fork is never owned, whoever opened it (ADR-0060 §6). Unlike
	// GitHub, Forgejo puts the PR in a comment's payload too, so the rule holds
	// for comments. Forgejo drops that PR when it cannot build it (a git error
	// in convert.ToAPIPullRequest): a PR comment without it is not owned.
	if pl.PullRequest != nil {
		head := pl.PullRequest.Head.Repo
		if head == nil || head.FullName != pl.Repository.FullName {
			threadOwned = false
		}
	} else if pl.IsPull {
		threadOwned = false
	}
	if pl.Run != nil && pl.Run.IsForkPullRequest {
		threadOwned = false
	}

	kindOf := event.ActorHuman
	// ponytail: Forgejo users carry no bot type; a bot is a human here unless
	// listed in BRIDGE_AGENT_LOGINS. Match known bot logins if routing needs it.
	if p.Agents[actor.Login] {
		kindOf = event.ActorAgent
	}

	return event.Event{
		ID:           delivery,
		Source:       "git.bnei.dev/" + pl.Repository.FullName,
		Type:         "dev.bnei.forge." + name + "." + action,
		Subject:      subject,
		Time:         now,
		Data:         body,
		Actor:        kindOf,
		ActorLogin:   actor.Login,
		ActorTrusted: actorTrusted,
		ThreadOwned:  threadOwned,
	}, nil
}
