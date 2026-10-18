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
	Trusted: map[string]bool{"MohammadBnei": true, "renovate[bot]": true, "ukubi-fleet": true},
	Agents:  map[string]bool{"ukubi-fleet": true},
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
	return []byte(fmt.Sprintf(`{"action":"opened","sender":{"login":%q},"repository":{"full_name":"MohammadBnei/editable-blog"},
"pull_request":{"number":42,"user":{"login":%q,"type":%q},"head":{"repo":{"full_name":%q}}}}`, sender, author, typ, head))
}

func TestNormalizeTrust(t *testing.T) {
	const home = "MohammadBnei/editable-blog"
	cases := []struct {
		name    string
		body    []byte
		trusted bool
		actor   string
	}{
		{"operator PR", pr("MohammadBnei", "MohammadBnei", "User", home), true, event.ActorHuman},
		{"renovate PR", pr("renovate[bot]", "renovate[bot]", "Bot", home), true, event.ActorBot},
		{"fleet agent PR", pr("ukubi-fleet", "ukubi-fleet", "User", home), true, event.ActorAgent},
		{"outsider PR", pr("stranger", "stranger", "User", home), false, event.ActorHuman},
		// Trust follows the author, not the sender.
		{"outsider PR, trusted sender", pr("MohammadBnei", "stranger", "User", home), false, event.ActorHuman},
		{"trusted author from a fork", pr("MohammadBnei", "MohammadBnei", "User", "MohammadBnei/fork"), false, event.ActorHuman},
	}
	for _, c := range cases {
		e, err := Normalize(policy, "pull_request", "d-1", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.Trusted != c.trusted || e.Actor != c.actor {
			t.Errorf("%s: trusted=%v actor=%s, want %v %s", c.name, e.Trusted, e.Actor, c.trusted, c.actor)
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
		name    string
		body    []byte
		trusted bool
	}{
		{"outsider on outsider PR", comment("stranger", "stranger"), false},
		{"outsider on trusted PR", comment("stranger", "MohammadBnei"), false},
		// Trust needs both: a trusted comment must not adopt an outsider's PR.
		{"trusted on outsider PR", comment("MohammadBnei", "stranger"), false},
		{"trusted on trusted PR", comment("MohammadBnei", "renovate[bot]"), true},
	}
	for _, c := range cases {
		e, err := Normalize(policy, "issue_comment", "d-2", c.body, time.Unix(0, 0))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if e.Subject != "github/MohammadBnei/editable-blog/pr/7" || e.Trusted != c.trusted {
			t.Errorf("%s: subject=%s trusted=%v, want trusted=%v", c.name, e.Subject, e.Trusted, c.trusted)
		}
	}
}

func TestNormalizeIgnored(t *testing.T) {
	for _, kc := range [][2]string{{"check_run", "completed"}, {"push", ""}, {"pull_request", "labeled"}} {
		body := []byte(`{"action":"` + kc[1] + `","repository":{"full_name":"a/b"}}`)
		if _, err := Normalize(policy, kc[0], "d", body, time.Unix(0, 0)); !errors.Is(err, ErrIgnored) {
			t.Errorf("%v: err=%v, want ErrIgnored", kc, err)
		}
	}
}
