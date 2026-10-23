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
	core, game, push := cs["bridge-core"], cs["bridge-game"], cs["bridge-push"]
	if !core.Privileged || game.Privileged || push.Privileged {
		t.Fatal("only bridge-core is privileged")
	}
	human := []string{"dev.bnei.fleet.session.", "dev.bnei.game."}
	for _, ty := range human {
		if core.mayRead([]string{ty}, nil) {
			t.Errorf("bridge-core can read %s", ty)
		}
	}
	if game.mayRead([]string{"dev.bnei.fleet.session."}, []string{"fleet/client/other/*"}) ||
		!game.mayRead([]string{"dev.bnei.fleet.session."}, []string{"fleet/client/game/*"}) {
		t.Error("bridge-game reads exactly its own sessions")
	}
	if push.mayRead([]string{"dev.bnei.github."}, nil) || len(push.PublishTypes) != 0 {
		t.Error("bridge-push reads only needs_you and publishes nothing")
	}
}
