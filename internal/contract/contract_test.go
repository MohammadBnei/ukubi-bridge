package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const real = "../../contract/events.yaml"

func TestLoadRules(t *testing.T) {
	cur.Store(nil)
	if Loaded() || Known("dev.bnei.forge.issues.opened") {
		t.Fatal("nothing loaded: not Loaded, nothing Known")
	}
	if err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || Loaded() {
		t.Fatal("a missing file must fail and load nothing")
	}
	if err := Load(real); err != nil {
		t.Fatal(err)
	}
	if !Loaded() || !Known("dev.bnei.forge.issues.opened") || !Known("dev.bnei.agent.anything") || Known("dev.bnei.nope.x") || Known("dev.bnei.agent") {
		t.Fatal("exact types and the dev.bnei.agent.* prefix are Known, the rest not")
	}
	// A broken file keeps the last good contract.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("types: [{type: nope}]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(bad); err == nil || !Known("dev.bnei.forge.issues.opened") {
		t.Fatal("a bad file must fail and keep the last good one")
	}
}

// Every dev.bnei.* literal the non-test sources emit as a whole type (kwatch's, core-facing ones) is in the
// contract. Prefixes (ending in a dot) are client-table grants, not types. The adapters that build their types
// from a payload (forgejo, github, alert) have their own constructor tests.
func TestSourceLiteralsContracted(t *testing.T) {
	if err := Load(real); err != nil {
		t.Fatal(err)
	}
	lit := regexp.MustCompile(`"(dev\.bnei\.[a-z_.]*[a-z_])"`)
	seen := 0
	for _, dir := range []string{"../../cmd", "../../internal"} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, _ := os.ReadFile(p)
			for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
				seen++
				if !Known(m[1]) {
					t.Errorf("%s emits %s: not in contract/events.yaml", p, m[1])
				}
			}
			return nil
		})
	}
	if seen < 4 {
		t.Errorf("%d literals: the check no longer sees kwatch's types", seen)
	}
}

// The shipped file passes the strict check (unknown fields, enums), which the runtime parser skips so an old
// image accepts a newer contract.
func TestRealStrict(t *testing.T) {
	b, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStrict(b); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte("types:\n  - {type: dev.bnei.a.b, owner: x}\nnew_top: 1\n")); err != nil {
		t.Errorf("an old image must ignore new fields: %v", err)
	}
	if _, err := ParseStrict([]byte("types:\n  - {type: dev.bnei.a.b, owner: x}\n")); err == nil {
		t.Error("strict must reject unknown fields")
	}
	if strings.Contains(string(b), "{{") {
		t.Error(`"{{" would be rendered by the chart's tpl`)
	}
}

func TestPrefixForm(t *testing.T) {
	for _, ty := range []string{"dev.bnei.*", "dev.bnei.agent*", "dev.bnei.a*.b", "dev.bnei.a.*.b"} {
		if _, err := Parse([]byte("types:\n  - {type: \"" + ty + "\"}\n")); err == nil {
			t.Errorf("%s accepted", ty)
		}
	}
	if _, err := Parse([]byte("types:\n  - {type: \"dev.bnei.agent.*\"}\n")); err != nil {
		t.Error(err)
	}
}
