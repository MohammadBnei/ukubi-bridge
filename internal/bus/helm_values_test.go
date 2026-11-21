package bus

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The client table shipped in helm/values.yaml must parse, and keep the
// privilege and read boundaries ADR-0066 sets.
func TestHelmClientTable(t *testing.T) {
	b, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)name: BRIDGE_API_CLIENTS\n\s+value: \|\n((?:\s{6}.*\n)+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("BRIDGE_API_CLIENTS block not found")
	}
	cs, err := ParseClients(strings.TrimSpace(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	core, game, push, atlas := cs["bridge-core"], cs["bridge-game"], cs["bridge-push"], cs["bridge-atlas"]
	for name, c := range cs {
		if c.Privileged != (name == "bridge-core") {
			t.Errorf("%s: privileged %v; only bridge-core is", name, c.Privileged)
		}
		if c.Tag != (name == "bridge-atlas") {
			t.Errorf("%s: tag %v; only bridge-atlas tags", name, c.Tag)
		}
	}
	// Atlas reads every type, Forgejo's included, and publishes nothing.
	if len(atlas.PublishTypes)+len(atlas.PublishSubjects) != 0 || !atlas.mayRead([]string{"dev.bnei."}, nil) {
		t.Errorf("bridge-atlas: %+v", atlas)
	}
	if !core.mayRead([]string{"dev.bnei.forge.", "dev.bnei.github."}, nil) {
		t.Error("bridge-core reads the forge events")
	}
	// No rule of core's may reach a human-facing type, on any subject; push's
	// rules reach only needs_you. Checked on the rule prefixes themselves.
	reaches := func(c Client, ty string) bool {
		for _, r := range c.Subscribe {
			for _, p := range r.Types {
				if strings.HasPrefix(ty, p) || strings.HasPrefix(p, ty) {
					return true
				}
			}
		}
		return false
	}
	for _, ty := range []string{"dev.bnei.fleet.session.", "dev.bnei.game."} {
		if reaches(core, ty) {
			t.Errorf("bridge-core can read %s", ty)
		}
	}
	for _, r := range push.Subscribe {
		for _, p := range r.Types {
			if !strings.HasPrefix(p, "dev.bnei.game.needs_you.") {
				t.Errorf("bridge-push reads %s", p)
			}
		}
	}
	if game.mayRead([]string{"dev.bnei.fleet.session."}, []string{"fleet/client/other/*"}) ||
		!game.mayRead([]string{"dev.bnei.fleet.session."}, []string{"fleet/client/game/*"}) {
		t.Error("bridge-game reads exactly its own sessions")
	}
	if len(push.PublishTypes) != 0 {
		t.Error("bridge-push publishes nothing")
	}
}
