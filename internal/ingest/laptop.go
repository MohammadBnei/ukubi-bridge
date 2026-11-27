package ingest

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// PostCreated is the type of the laptop route's one event.
const PostCreated = "dev.bnei.laptop.post.created"

// maxText is how many runes a post's text holds, after masking. A longer one is refused, never cut.
const maxText = 2000

// The other limits of a post.
const (
	maxLabel    = 60  // runes kept: a label is clamped
	maxRawLabel = 200 // runes received
	maxName     = 200
	maxAbout    = 10
	maxNumber   = 999_999_999
	maxNeeds    = 10
	maxNeed     = 200
)

// post is what a post says: the body's fields and the stored data's, no other. needs_you nil is absent; empty clears.
type post struct {
	Session      string    `json:"session"`
	SessionLabel string    `json:"session_label,omitempty"`
	Repo         string    `json:"repo,omitempty"`
	Branch       string    `json:"branch,omitempty"`
	PostID       string    `json:"post_id"`
	Text         string    `json:"text"` // Markdown, kept as text
	About        []about   `json:"about,omitempty"`
	NeedsYou     *[]string `json:"needs_you,omitempty"`
	Corrects     string    `json:"corrects,omitempty"`
}

// about is a PR or an issue of a listed repo.
type about struct {
	Repo   string `json:"repo"`
	Number int    `json:"number"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

// Post builds the event of one post: its id is post/<session>/<post_id>, so a retry is one event and two posts are two.
// repos are the repos about may name. Its error is ctx's once ctx is done. It also returns the fields it masked something in, with an error too. An error's
// words name a field and a limit, never a value: they are the answer.
func Post(ctx context.Context, body []byte, repos map[string]bool, now time.Time) (event.Event, []string, error) {
	// v2: names match exactly; duplicate names, trailing data and invalid UTF-8 are errors. The map pass refuses null,
	// which would read as absent.
	var fields map[string]jsontext.Value
	var p post
	if jsonv2.Unmarshal(body, &fields) != nil || slices.ContainsFunc(values(fields), func(v jsontext.Value) bool { return v.Kind() == 'n' }) ||
		jsonv2.Unmarshal(body, &p, jsonv2.RejectUnknownMembers(true)) != nil {
		return event.Event{}, nil, errors.New("body: not a JSON object of the fields session, session_label, repo, branch, post_id, text, about, needs_you and corrects, each of its type")
	}
	if err := p.check(repos, maxRawLabel); err != nil {
		return event.Event{}, nil, err
	}
	select {
	case masking <- struct{}{}:
		defer func() { <-masking }()
	case <-ctx.Done():
		return event.Event{}, nil, ctx.Err()
	}
	var hidden []string
	var stopped error
	mask := func(field, s string) string {
		m, err := Mask(ctx, s)
		if err != nil {
			stopped = err
		} else if m != Clean(s) {
			hidden = append(hidden, field)
		}
		return strings.TrimSpace(m)
	}
	line := func(field, s string) string { return strings.Join(strings.Fields(mask(field, s)), " ") }
	p.Text = mask("text", p.Text)
	if p.SessionLabel = line("session_label", p.SessionLabel); utf8.RuneCountInString(p.SessionLabel) > maxLabel {
		p.SessionLabel = strings.TrimSpace(string([]rune(p.SessionLabel)[:maxLabel]))
	}
	p.Repo, p.Branch = line("repo", p.Repo), line("branch", p.Branch)
	if p.NeedsYou != nil {
		for i, s := range *p.NeedsYou {
			(*p.NeedsYou)[i] = line(fmt.Sprintf("needs_you[%d]", i), s)
		}
	}
	if stopped != nil {
		return event.Event{}, nil, stopped
	}
	if err := p.check(repos, maxLabel); err != nil {
		return event.Event{}, hidden, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return event.Event{}, hidden, errors.New("body: cannot be stored")
	}
	return event.Event{
		ID:      "post/" + p.Session + "/" + p.PostID,
		Source:  LaptopSource,
		Type:    PostCreated,
		Subject: "laptop/session/" + p.Session,
		Time:    now,
		Data:    data,
		Actor:   event.ActorMachine,
		// Neither trust fact, no owner, no cause: the body cannot name one.
	}, hidden, nil
}

func values(m map[string]jsontext.Value) []jsontext.Value {
	var vs []jsontext.Value
	for _, v := range m {
		vs = append(vs, v)
	}
	return vs
}

// masking is held while one post is masked.
var masking = make(chan struct{}, 1)

// check holds a post to its limits.
func (p post) check(repos map[string]bool, label int) error {
	n := utf8.RuneCountInString
	switch {
	case !uuid.MatchString(p.Session):
		return errors.New("session: not a lowercase UUID")
	case !uuid.MatchString(p.PostID):
		return errors.New("post_id: not a lowercase UUID")
	case p.Corrects != "" && (!uuid.MatchString(p.Corrects) || p.Corrects == p.PostID):
		return errors.New("corrects: not the post_id of another post")
	case n(p.SessionLabel) > label:
		return fmt.Errorf("session_label: over %d characters", label)
	case n(p.Repo) > maxName:
		return fmt.Errorf("repo: over %d characters", maxName)
	case n(p.Branch) > maxName:
		return fmt.Errorf("branch: over %d characters", maxName)
	case strings.TrimSpace(p.Text) == "":
		return errors.New("text: empty")
	case n(p.Text) > maxText:
		return fmt.Errorf("text: %d characters, the limit is %d", n(p.Text), maxText)
	case len(p.About) > maxAbout:
		return fmt.Errorf("about: over %d entries", maxAbout)
	}
	for i, a := range p.About {
		if !repos[a.Repo] {
			return fmt.Errorf("about[%d].repo: not a listed repo", i)
		}
		if a.Number < 1 || a.Number > maxNumber {
			return fmt.Errorf("about[%d].number: not 1 to %d", i, maxNumber)
		}
	}
	if p.NeedsYou == nil {
		return nil
	}
	if len(*p.NeedsYou) > maxNeeds {
		return fmt.Errorf("needs_you: over %d entries", maxNeeds)
	}
	for i, s := range *p.NeedsYou {
		if strings.TrimSpace(s) == "" || n(s) > maxNeed {
			return fmt.Errorf("needs_you[%d]: not 1 to %d characters", i, maxNeed)
		}
	}
	return nil
}
