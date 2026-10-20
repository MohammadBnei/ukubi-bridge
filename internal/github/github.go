// Package github turns GitHub App webhook deliveries into bus events.
package github

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
)

// Verify checks X-Hub-Signature-256 against the webhook secret.
func Verify(secret, body []byte, header string) bool {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

// Policy says who is trusted and who is a fleet agent. Logins are GitHub logins.
type Policy struct {
	Trusted map[string]bool // logins whose own actions may open threads: the operator, CI
	// Agents are fleet agent identities, tagged actor=agent and never trusted:
	// all agents share one GitHub identity, so a prompt-injected session
	// acting through it would otherwise re-enter the bus as a clean, trusted
	// event. Agent hand-offs that carry trust go through core PublishEvent.
	Agents map[string]bool
}

// owns reports whether threads authored by login are the operator's own:
// trusted logins, and the fleet agents working for the operator. Only a
// trusted actor's event on such a thread is trusted.
func (p Policy) owns(login string) bool {
	return p.Trusted[login] || p.Agents[login]
}

// allowed lists the accepted event/action pairs. check_run, status and push
// fan out per commit and would wake agents in a loop (ADR-0060 §5).
var allowed = map[string]map[string]bool{
	"pull_request":        {"opened": true, "synchronize": true, "closed": true, "reopened": true},
	"issue_comment":       {"created": true},
	"pull_request_review": {"submitted": true},
}

// ErrIgnored means the delivery is valid but not an event the bus carries.
var ErrIgnored = errors.New("event type not carried")

type user struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

type repo struct {
	FullName string `json:"full_name"`
}

type payload struct {
	Action      string `json:"action"`
	Sender      user   `json:"sender"`
	Repository  repo   `json:"repository"`
	PullRequest *struct {
		Number int  `json:"number"`
		User   user `json:"user"`
		Head   struct {
			Repo *repo `json:"repo"` // nil when the fork was deleted
		} `json:"head"`
	} `json:"pull_request"`
	Issue *struct {
		Number      int       `json:"number"`
		User        user      `json:"user"`
		PullRequest *struct{} `json:"pull_request"`
	} `json:"issue"`
	Comment *struct {
		User user `json:"user"`
	} `json:"comment"`
	Review *struct {
		User user `json:"user"`
	} `json:"review"`
}

// Normalize builds the bus event for one delivery. kind is X-GitHub-Event,
// delivery is X-GitHub-Delivery.
func Normalize(p Policy, kind, delivery string, body []byte, now time.Time) (event.Event, error) {
	var pl payload
	if err := json.Unmarshal(body, &pl); err != nil {
		return event.Event{}, fmt.Errorf("decode %s: %w", kind, err)
	}
	if !allowed[kind][pl.Action] {
		return event.Event{}, ErrIgnored
	}
	if pl.Repository.FullName == "" || delivery == "" {
		return event.Event{}, errors.New("missing repository or delivery id")
	}

	// The actor is whoever wrote the thing, and author is whoever owns the
	// thread. A PR's opened event is the author's; synchronize, closed and
	// reopened are the sender's (the pusher, the closer): attributing a push
	// to the PR author would let anyone with push access act as them.
	var actor, author user
	var subject string
	switch kind {
	case "pull_request":
		if pl.PullRequest == nil {
			return event.Event{}, errors.New("pull_request event without pull_request")
		}
		actor, author = pl.PullRequest.User, pl.PullRequest.User
		if pl.Action != "opened" {
			actor = pl.Sender
		}
		subject = fmt.Sprintf("github/%s/pr/%d", pl.Repository.FullName, pl.PullRequest.Number)
	case "issue_comment":
		if pl.Issue == nil || pl.Comment == nil {
			return event.Event{}, errors.New("issue_comment without issue or comment")
		}
		actor, author = pl.Comment.User, pl.Issue.User
		thread := "issue"
		if pl.Issue.PullRequest != nil {
			thread = "pr"
		}
		subject = fmt.Sprintf("github/%s/%s/%d", pl.Repository.FullName, thread, pl.Issue.Number)
	case "pull_request_review":
		if pl.PullRequest == nil || pl.Review == nil {
			return event.Event{}, errors.New("pull_request_review without pull_request or review")
		}
		actor, author = pl.Review.User, pl.PullRequest.User
		subject = fmt.Sprintf("github/%s/pr/%d", pl.Repository.FullName, pl.PullRequest.Number)
	}

	// Both are needed: a trusted login acting on an outsider's thread must
	// not adopt it, and an outsider acting on the operator's thread is not
	// the operator. An empty login (no sender) is never trusted.
	trusted := p.Trusted[actor.Login] && p.owns(author.Login)
	// A PR from a fork is never trusted, whoever opened it (ADR-0060 §6).
	if pl.PullRequest != nil {
		head := pl.PullRequest.Head.Repo
		if head == nil || head.FullName != pl.Repository.FullName {
			trusted = false
		}
	}

	return event.Event{
		ID:         delivery,
		Source:     "github.com/" + pl.Repository.FullName,
		Type:       "dev.bnei.github." + kind + "." + pl.Action,
		Subject:    subject,
		Time:       now,
		Data:       body,
		Actor:      actorKind(p, actor),
		ActorLogin: actor.Login,
		Trusted:    trusted,
	}, nil
}

func actorKind(p Policy, u user) string {
	switch {
	case p.Agents[u.Login]:
		return event.ActorAgent
	case u.Type == "Bot" || strings.HasSuffix(u.Login, "[bot]"):
		return event.ActorBot
	default:
		return event.ActorHuman
	}
}
