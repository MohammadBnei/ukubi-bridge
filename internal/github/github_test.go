package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

var policy = Policy{
	Trusted: map[string]bool{"MohammadBnei": true},
	Agents:  map[string]bool{"ukubi-fleet[bot]": true},
}

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerify(t *testing.T) {
	body := `{"a":1}`
	if !Verify([]byte("s"), []byte(body), sign("s", body)) {
		t.Fatal("valid signature rejected")
	}
	for _, h := range []string{"", "sha256=zz", sign("other", body), "sha1=" + sign("s", body)[7:]} {
		if Verify([]byte("s"), []byte(body), h) {
			t.Fatalf("bad signature %q accepted", h)
		}
	}
}

func pr(sender, author, typ, head string) []byte {
	return prAction("opened", sender, author, typ, head)
}

func prAction(action, sender, author, typ, head string) []byte {
	return []byte(fmt.Sprintf(`{"action":%q,"sender":{"login":%q},"repository":{"full_name":"MohammadBnei/editable-blog"},
"pull_request":{"number":42,"user":{"login":%q,"type":%q},"head":{"repo":{"full_name":%q}}}}`, action, sender, author, typ, head))
}

func TestNormalizeTrust(t *testing.T) {
	const home = "MohammadBnei/editable-blog"
	cases := []struct {
		name          string
		body          []byte
		actor, thread bool
		kind          string
	}{
		{"operator PR", pr("MohammadBnei", "MohammadBnei", "User", home), true, true, event.ActorHuman},
		// Release notes in a Renovate body are third-party text.
		{"renovate PR", pr("renovate[bot]", "renovate[bot]", "Bot", home), false, false, event.ActorBot},
		// Agents share one identity: an agent is never a trusted actor.
		{"fleet agent PR", pr("ukubi-fleet[bot]", "ukubi-fleet[bot]", "Bot", home), false, true, event.ActorAgent},
		{"outsider PR", pr("stranger", "stranger", "User", home), false, false, event.ActorHuman},
		// opened is the author's action, not the sender's.
		{"outsider PR, trusted sender", pr("MohammadBnei", "stranger", "User", home), false, false, event.ActorHuman},
		{"trusted author from a fork", pr("MohammadBnei", "MohammadBnei", "User", "MohammadBnei/fork"), true, false, event.ActorHuman},
	}
	for _, c := range cases {
		e, err := Normalize(policy, "pull_request", "d-1", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.ActorTrusted != c.actor || e.ThreadOwned != c.thread || e.Actor != c.kind {
			t.Errorf("%s: actorTrusted=%v threadOwned=%v actor=%s, want %v %v %s", c.name, e.ActorTrusted, e.ThreadOwned, e.Actor, c.actor, c.thread, c.kind)
		}
		if e.Subject != "github/"+home+"/pr/42" || e.Type != "dev.bnei.github.pull_request.opened" || e.ID != "d-1" {
			t.Errorf("%s: envelope %+v", c.name, e)
		}
	}
}

func comment(commenter, author string) []byte {
	return []byte(fmt.Sprintf(`{"action":"created","sender":{"login":%q},"repository":{"full_name":"MohammadBnei/editable-blog"},
"issue":{"number":7,"user":{"login":%q},"pull_request":{}},"comment":{"user":{"login":%q,"type":"User"}}}`, commenter, author, commenter))
}

func TestNormalizeComment(t *testing.T) {
	cases := []struct {
		name          string
		body          []byte
		actor, thread bool
	}{
		{"outsider on outsider PR", comment("stranger", "stranger"), false, false},
		{"outsider on trusted PR", comment("stranger", "MohammadBnei"), false, true},
		// Two facts: a trusted comment does not adopt an outsider's PR.
		{"trusted on outsider PR", comment("MohammadBnei", "stranger"), true, false},
		{"trusted on trusted PR", comment("MohammadBnei", "MohammadBnei"), true, true},
		// The operator steering a fleet PR from GitHub stays trusted...
		{"trusted on agent PR", comment("MohammadBnei", "ukubi-fleet[bot]"), true, true},
		// ...but an agent's own comment never is.
		{"agent on trusted PR", comment("ukubi-fleet[bot]", "MohammadBnei"), false, true},
	}
	for _, c := range cases {
		e, err := Normalize(policy, "issue_comment", "d-2", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.Subject != "github/MohammadBnei/editable-blog/pr/7" || e.ActorTrusted != c.actor || e.ThreadOwned != c.thread {
			t.Errorf("%s: subject=%s actorTrusted=%v threadOwned=%v, want %v %v", c.name, e.Subject, e.ActorTrusted, e.ThreadOwned, c.actor, c.thread)
		}
	}
}

// synchronize, closed and reopened are the sender's actions, not the author's.
func TestNormalizePRActions(t *testing.T) {
	const home = "MohammadBnei/editable-blog"
	cases := []struct {
		name          string
		body          []byte
		actor, thread bool
		kind          string
	}{
		{"operator pushes own PR", prAction("synchronize", "MohammadBnei", "MohammadBnei", "User", home), true, true, event.ActorHuman},
		{"agent pushes operator PR", prAction("synchronize", "ukubi-fleet[bot]", "MohammadBnei", "User", home), false, true, event.ActorAgent},
		{"operator pushes agent PR", prAction("synchronize", "MohammadBnei", "ukubi-fleet[bot]", "Bot", home), true, true, event.ActorHuman},
		{"outsider closes operator PR", prAction("closed", "stranger", "MohammadBnei", "User", home), false, true, event.ActorHuman},
		{"no sender", prAction("reopened", "", "MohammadBnei", "User", home), false, true, event.ActorHuman},
	}
	for _, c := range cases {
		e, err := Normalize(policy, "pull_request", "d-3", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.ActorTrusted != c.actor || e.ThreadOwned != c.thread || e.Actor != c.kind {
			t.Errorf("%s: actorTrusted=%v threadOwned=%v actor=%s, want %v %v %s", c.name, e.ActorTrusted, e.ThreadOwned, e.Actor, c.actor, c.thread, c.kind)
		}
	}
}

func review(reviewer, author string) []byte {
	return []byte(fmt.Sprintf(`{"action":"submitted","sender":{"login":%q},"repository":{"full_name":"MohammadBnei/editable-blog"},
"pull_request":{"number":42,"user":{"login":%q},"head":{"repo":{"full_name":"MohammadBnei/editable-blog"}}},"review":{"user":{"login":%q}}}`, reviewer, author, reviewer))
}

// A review follows the comment rule: trusted reviewer on an owned PR.
func TestNormalizeReview(t *testing.T) {
	for _, c := range []struct {
		name          string
		body          []byte
		actor, thread bool
	}{
		{"operator on own PR", review("MohammadBnei", "MohammadBnei"), true, true},
		{"operator on agent PR", review("MohammadBnei", "ukubi-fleet[bot]"), true, true},
		{"operator on outsider PR", review("MohammadBnei", "stranger"), true, false},
		{"outsider on operator PR", review("stranger", "MohammadBnei"), false, true},
	} {
		e, err := Normalize(policy, "pull_request_review", "d-4", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.ActorTrusted != c.actor || e.ThreadOwned != c.thread {
			t.Errorf("%s: actorTrusted=%v threadOwned=%v, want %v %v", c.name, e.ActorTrusted, e.ThreadOwned, c.actor, c.thread)
		}
	}
}

func TestNormalizeIgnored(t *testing.T) {
	for _, kc := range [][2]string{{"check_run", "completed"}, {"push", ""}, {"pull_request", "edited"}, {"issues", "closed"}} {
		body := []byte(`{"action":"` + kc[1] + `","repository":{"full_name":"a/b"}}`)
		if _, err := Normalize(policy, kc[0], "d", body, time.Unix(0, 0)); !errors.Is(err, ErrIgnored) {
			t.Errorf("%v: err=%v, want ErrIgnored", kc, err)
		}
	}
}

func issue(action, sender, author string) []byte {
	return []byte(fmt.Sprintf(`{"action":%q,"sender":{"login":%q},"repository":{"full_name":"MohammadBnei/editable-blog"},
"issue":{"number":9,"user":{"login":%q}},"label":{"name":"dev-notes"}}`, action, sender, author))
}

// Labels and issues (agent-fleet ADR-0082 §12): the owner's label or
// @mention addresses an agent, so these reach the bus too.
func TestNormalizeLabelsAndIssues(t *testing.T) {
	const home = "MohammadBnei/editable-blog"
	cases := []struct {
		name, kind, subject string
		body                []byte
		actor, thread       bool
	}{
		{"operator opens an issue", "issues", "issue/9", issue("opened", "MohammadBnei", "MohammadBnei"), true, true},
		{"stranger opens an issue", "issues", "issue/9", issue("opened", "stranger", "stranger"), false, false},
		// labeled is the sender's action: the owner labelling a stranger's issue.
		{"operator labels a stranger's issue", "issues", "issue/9", issue("labeled", "MohammadBnei", "stranger"), true, false},
		{"stranger labels the operator's issue", "issues", "issue/9", issue("labeled", "stranger", "MohammadBnei"), false, true},
		{"operator labels own PR", "pull_request", "pr/42", prAction("labeled", "MohammadBnei", "MohammadBnei", "User", home), true, true},
		{"operator labels a fork PR", "pull_request", "pr/42", prAction("labeled", "MohammadBnei", "stranger", "User", "stranger/fork"), true, false},
	}
	for _, c := range cases {
		e, err := Normalize(policy, c.kind, "d-5", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.Subject != "github/"+home+"/"+c.subject || e.ActorTrusted != c.actor || e.ThreadOwned != c.thread {
			t.Errorf("%s: subject=%s actorTrusted=%v threadOwned=%v, want %s %v %v", c.name, e.Subject, e.ActorTrusted, e.ThreadOwned, c.subject, c.actor, c.thread)
		}
	}
}
