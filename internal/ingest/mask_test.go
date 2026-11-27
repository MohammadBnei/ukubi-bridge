package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every value here is made up, derived from a counter: nothing in this file is or was a credential.

// fake is n made-up characters of alphabet.
func fake(alphabet string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		sum := sha256.Sum256(fmt.Appendf(nil, "not a credential %d", i))
		for _, x := range sum {
			b.WriteByte(alphabet[int(x)%len(alphabet)])
		}
	}
	return b.String()[:n]
}

const (
	alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexes = "0123456789abcdef"
)

// leak is a run of n characters of s that out still holds.
func leak(s, out string, n int) string {
	for i := 0; i+n <= len(s); i++ {
		if w := s[i : i+n]; strings.Contains(out, w) {
			return w
		}
	}
	return ""
}

func mask(t *testing.T, s string) string {
	t.Helper()
	m, err := Mask(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func tokens() []string {
	a := fake(alnum, 60)
	var ts []string
	for _, p := range []string{"ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "glrt-", "glcbt-", "glsa_", "xoxb-", "xapp-", "xoxe.", "sk-ant-", "sk-proj-", "sk_live_", "rk_test_",
		"whsec_", "npm_", "pypi-", "dckr_pat_", "dop_v1_", "hf_", "ya29.", "GOCSPX-", "hvs.", "tskey-", "lin_api_", "ntn_", "xai-", "gsk_", "shpat_", "AGE-SECRET-KEY-", "SG."} {
		ts = append(ts, p+a[:12])
	}
	return append(ts, "sk-"+a[:20], "st."+fake(hexes, 14)+"."+a[:8], "ua."+a[:14], "AKIA"+fake(upper, 16), "ASIA"+fake(upper, 16), "AIza"+a[:24], "eyJ"+a[:12]+".eyJ"+a[12:24]+"."+a[24:40],
		"123456789:"+fake("abcdefghijklmnopqrstuvwxyz0123456789_", 34), "M"+a[:24]+"."+a[:6]+"."+a[10:36])
}

func TestMaskTokens(t *testing.T) {
	for n, s := range tokens() {
		mid := max(len(s)/2, strings.IndexAny(s, "_-.:")+3)
		for i, text := range []string{
			s, "see " + s + " there", `x="` + s + `",`, `{"a":"` + s + `","b":1}`, `"{\"a\":\"` + s + `\"}"`, "```sh\nrun " + s + "\n```\n", "`" + s + "`", "**" + s + "**",
			"| a | b |\n|---|---|\n| x | " + s + " |\n", "|x|" + s + "|", "[" + s + "](https://git.bnei.dev)", "[x](" + s + ")", "(" + s + ").",
			strings.Join(strings.Split(s, ""), "\u200b"), s[:mid] + "\u202e" + s[mid:], s[:mid] + "\u00ad" + s[mid:], s[:mid] + "\x00" + s[mid:], s[:mid] + "\u0301" + s[mid:],
			s[:mid] + "%E2%80%8B" + s[mid:], s[:mid] + "\r\n" + s[mid:], s[:mid] + `\r\n` + s[mid:], s[:mid] + "\n" + s[mid:], "it is\n" + s[:mid] + "\n" + s[mid:],
			s[:mid] + "\n    " + s[mid:], "> " + s[:mid] + "\n> " + s[mid:], s[:mid] + "\\\n" + s[mid:], `"` + s[:mid] + `" + "` + s[mid:] + `"`, s[:mid] + `"` + s[mid:], s[:mid] + "**" + s[mid:] + "**",
		} {
			if w := leak(s, mask(t, text), 6); w != "" && !strings.HasPrefix(s, w) && !strings.HasPrefix("AGE-SECRET-KEY-github_pat_", w) && !strings.Contains("AGE-SECRET-KEY-github_pat_dckr_pat_dop_v1_sk-proj-", w) {
				t.Errorf("token %d, form %d: %q", n, i, w)
			}
		}
		for i, enc := range []func(string) string{percent, func(s string) string { return strings.ReplaceAll(percent(s), "%", "%25") }, jsonUnicode, hexEscapes, entities, fullWidth} {
			rest := s[strings.LastIndexAny(s, "_-.:")+1:]
			out := mask(t, "x = "+enc(s))
			for j := 0; j+3 <= len(rest); j++ {
				if strings.Contains(out, enc(rest[j:j+3])) {
					t.Errorf("token %d, encoding %d: %q", n, i, out)
					break
				}
			}
		}
	}
}

func each(s string, f func(byte) string) string {
	var b strings.Builder
	for i := range len(s) {
		b.WriteString(f(s[i]))
	}
	return b.String()
}
func percent(s string) string {
	return each(s, func(c byte) string { return "%" + hex.EncodeToString([]byte{c}) })
}
func jsonUnicode(s string) string {
	return each(s, func(c byte) string { return fmt.Sprintf(`\u%04x`, c) })
}
func hexEscapes(s string) string {
	return each(s, func(c byte) string { return fmt.Sprintf(`\x%02x`, c) })
}
func entities(s string) string {
	return each(s, func(c byte) string { return fmt.Sprintf("&#%02d;", c) })
}
func fullWidth(s string) string {
	return each(s, func(c byte) string { return string(rune(c) - 0x20 + 0xFF00) })
}

func TestMask(t *testing.T) {
	const v, long = "hunter22", "correcthorsebattery"
	for _, text := range []string{
		"password=" + v, "password: " + v, "Password : " + v, "PASSWD=" + v, "db_password = '" + v + "'", `"password":"` + v + `"`, `{\"password\":\"` + v + `\"}`, "password%3D" + v,
		"export API_KEY=" + v, "api-key: " + v, "apiKey: " + v, "x-api-key: " + v, "client_secret=" + v, "access_token=" + v, "private_key: " + v, "signing key: " + v, "passphrase: " + v,
		"auth_key: " + v, "credentials: " + v, "mot de passe : " + v, "mdp: " + v, "jeton = " + v, "secret -> " + v, "secret => " + v, "secret := " + v, "token\u2192" + v,
		"https://git.bnei.dev/x?token=" + v + "&x=1", "https://git.bnei.dev/x?a=1&api_key=" + v, "<password>" + v + "</password>", "password (prod): " + v, "password for prod: " + v,
		"the password is: " + v, "the password is " + v, "token was " + v, "secret set to " + v, "password is now " + v, "password changed to " + v, "the token has been rotated to " + v,
		"password " + v, "password `" + v + "`", "--password " + v, "--api-token " + v, "--api-token=" + v, "curl -u bob:" + v + " https://x", "curl --user bob:" + v, "**Password:** " + v, "**Password**: " + v,
		"**Password:**\n" + v, "__Password__: " + v, "`password`: `" + v + "`", "`password:`\n" + v, "- password: " + v, "| password | " + v + " |", "|password|" + v + "|", "[password](" + v + ")",
		"# Password\n" + v, "password:\n" + v, "password:\n\n  " + v, "password:\n```\n" + v + "\n```", "password:\n~~~\n" + v + "\n~~~", "~~~\nexport TOKEN=" + v + "\n~~~", "```\npassword=" + v,
		"> token: " + v, "password: |\n  x\n  " + v, "password: >-\n  " + v, "passwords:\n  - x\n  - " + v, "tokens:\n- \"" + v + "\"\n- y", `tokens: ["x", "` + v + `"]`, `password = "x" + "` + v + `"`,
		"p\u0430ssword: " + v, "pass\u03c9ord: " + v, "t\u043eken=" + v, "\u0422\u041eKEN=" + v, "password\u00a0:\u00a0" + v, "password\u1680:\u1680" + v,
		"ghp_ab\u0301" + fake(alnum, 20), "ghp_ab\\r\\n" + fake(alnum, 20), "gh\np_" + fake(alnum, 20), "it is\nsk-" + fake(alnum, 20)[:8] + "\n" + fake(alnum, 20)[8:], "ghp_abcdefGhijkl",
		"Bearer a" + v + v, "bearer: a" + v + v, "Authorization: Bearer " + v, "Authorization: Basic " + v + "=", "Cookie: a=b; c=" + v + v,
		"https://bob:" + v + "@git.bnei.dev/x", "https://a" + v + "@git.bnei.dev/x", "https://u:a%20" + v + "@git.bnei.dev/x", "postgres://bob:" + v + "@db/x",
		"https://discord.com/api/webhooks/1/" + v, "https://discordapp.com/api/v10/webhooks/1/" + v, "https://hooks.slack.com/services/T/B/" + v,
		"-----BEGIN RSA PRIVATE KEY-----\n" + v + "\n-----END RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + v, "-----BEGIN PRIVATE KEY-----\\n" + v + "\\n-----END PRIVATE KEY-----",
		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n" + v, "-----BEGIN%20PRIVATE%20KEY-----%0A" + v, "PuTTY-User-Key-File-3: x\n\na b " + v,
	} {
		if out := mask(t, text); strings.Contains(out, v) || !strings.Contains(out, masked) {
			t.Errorf("%q: %q", text, out)
		}
	}
	for text, v := range map[string]string{
		"password: " + long: long, `password: "two long words"`: "two long words", "token: " + fake(hexes, 8) + "a1": fake(hexes, 8), "secret=" + fake(hexes, 40): fake(hexes, 40), "code: 482913": "482913", "code is 482 913": "482",
		"pin 4821": "4821", "PIN: 4821": "4821", "otp=123456": "123456", "password: 4821": "4821", "x " + fake(alnum, 40): fake(alnum, 40), "aws " + fake(alnum, 20) + "/" + fake(alnum, 40)[20:]: fake(alnum, 20),
		"mot de passe : " + long: long, "x ABCDabcd1234EFGHefgh5678IJKLijkl": "ABCDabcd1234", "x abcdeF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0": "abcdeF1gH2",
	} {
		if out := mask(t, text); strings.Contains(out, v) {
			t.Errorf("%q: %q", text, out)
		}
	}
	h := fake(hexes, 64)
	for _, s := range []string{
		"Merged PR #52 at " + h[:7] + "; 14 tests pass.", h[:40], "image@sha256:" + h, h, "0f8fad5b-d9cb-469f-a165-70867728950e", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "platform-core-7d9c5b8f6d-x2x4q", "mountain-atlas-0",
		"See internal/forgejo/contract_test.go:123 and /Users/x/Code/ukubi/.wt/br-1/helm/values.yaml.", "https://git.bnei.dev/O/ukubi-bridge/commit/" + h[:40], "https://github.com/O/r/pull/52?w=1#issuecomment-123",
		"Auth: the login moved to the new flow", "| Auth | where |\n|---|---|\n| none | here |", "fix(auth): tell a replay from a retry", "Author: Bob", "feat/2026-11-24-feed-slice-6",
		"TestHelmClientTableContractedWithPostgres17 fails", "BRIDGE_GITHUB_WEBHOOK_SECRET", "password: DB_PASSWORD_2", "Authorization: ${AUTH_HEADER1}", "npm_config_cache_dir", "CF_TOKEN -> CF_DNS_API_TOKEN.", "secretName: ukubi-bridge-forgejo-2",
		"secret: ukubi-bridge-forgejo", "max tokens: 4096", "the token is 40 characters", "token: ${{ secrets.TOKEN1 }}", "password=$PASSWORD1", "token := mint1(ctx)", "Token: HS256", "`secrets: ` passes 2 of them",
		"exit code: 137000", "status code is 404000", "pin 1.4.4", "image pin 2026-11", "git@git.bnei.dev:O/r.git", "ssh://git@git.bnei.dev/O/r", "docker run -u 1000:1000", "ukubi-bridge:a1@sha256:" + h,
		"platform-authentik-server.authentik.svc.cluster.local", "192.0.2.14:8080 and v1.36.12", "```go\nfunc main() {}\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n", "Bearer authentication", "task-force-something-long-here",
		"- one\n\t- two\n\n> a quote\n\n**bold** `code` [link](https://git.bnei.dev/x/y)", "\u00c9crit \u00e0 14 h", "\u0442\u0435\u0441\u0442", "session_" + fake(alnum, 24),
	} {
		if out := mask(t, s); out != s {
			t.Errorf("%q: %q", s, out)
		}
	}
	for in, want := range map[string]string{
		"done. token=x1y2 next":                 "done. token=[masked] next",
		"token: x1y2\nand then more.":           "token: [masked]\nand then more.",
		"a\npassword: x1y2\n\nAnd then b.":      "a\npassword: [masked]\n\nAnd then b.",
		"see https://u:p@git.bnei.dev/x now":    "see https://[masked]@git.bnei.dev/x now",
		"https://git.bnei.dev/x?token=ab&b=2":   "https://git.bnei.dev/x?token=[masked]&b=2",
		"ghp_" + fake(alnum, 20) + ", then":     "ghp_[masked], then",
		"ghp_" + fake(alnum, 20) + "~rest then": "ghp_[masked] then",
	} {
		if got := mask(t, in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	in := "a\x00\x07b\u200b\u200e\u202e\u2066\u2069\ufeff\u00ad\u2060\u3164\ufe0f\U000e0041\ue000c\td\r\ne\u2028f\rg\u00a0h"
	if got, want := Clean(in), "abc\td\ne\nf\ng\u00a0h"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if out := mask(t, "x\xff y"); !utf8.ValidString(out) {
		t.Errorf("%q", out)
	}
}

func TestMaskStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if m, err := Mask(ctx, "x"); err == nil || m != "" {
		t.Errorf("%q %v", m, err)
	}
}

func TestLookalikes(t *testing.T) {
	var to []rune
	for from, r := range lookalikes {
		if from < utf8.RuneSelf && from != r || r >= utf8.RuneSelf {
			t.Errorf("%q to %q", from, r)
		}
		to = append(to, r)
	}
	for _, r := range "aceikmnopstuxy" {
		if !slices.Contains(to, r) && r != 'u' {
			t.Errorf("nothing looks like %q", r)
		}
	}
}
