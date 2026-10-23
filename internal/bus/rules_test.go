package bus

import (
	"strings"
	"testing"
)

func TestCovers(t *testing.T) {
	game := Rule{Types: []string{"dev.bnei.fleet.session."}, Subjects: []string{"fleet/client/game/"}}
	alerts := Rule{Types: []string{"dev.bnei.alert."}, Subjects: []string{""}}
	cases := []struct {
		name     string
		r        Rule
		types    []string
		subjects []string
		want     bool
	}{
		{"exact fit", game, []string{"dev.bnei.fleet.session."}, []string{"fleet/client/game/*"}, true},
		{"narrower type", game, []string{"dev.bnei.fleet.session.waiting"}, []string{"fleet/client/game/t1"}, true},
		{"no types asks for all", game, nil, []string{"fleet/client/game/*"}, false},
		{"empty type prefix", game, []string{""}, []string{"fleet/client/game/*"}, false},
		{"wider type", game, []string{"dev."}, []string{"fleet/client/game/*"}, false},
		{"other type", game, []string{"dev.bnei.github."}, []string{"fleet/client/game/*"}, false},
		{"no subjects asks for all", game, []string{"dev.bnei.fleet.session."}, nil, false},
		{"another client's sessions", game, []string{"dev.bnei.fleet.session."}, []string{"fleet/client/other/*"}, false},
		{"glob before the prefix ends", game, []string{"dev.bnei.fleet.session."}, []string{"fleet/client/game*"}, false},
		{"leading wildcard", game, []string{"dev.bnei.fleet.session."}, []string{"*"}, false},
		{"one subject outside", game, []string{"dev.bnei.fleet.session."}, []string{"fleet/client/game/a", "github/x"}, false},
		{"any subject rule, no subjects", alerts, []string{"dev.bnei.alert."}, nil, true},
		{"any subject rule, a glob", alerts, []string{"dev.bnei.alert.firing"}, []string{"alert/*"}, true},
		{"any subject rule, wrong type", alerts, []string{"dev.bnei.fleet.session."}, nil, false},
	}
	for _, c := range cases {
		if got := covers(c.r, c.types, c.subjects); got != c.want {
			t.Errorf("%s: covers = %v, want %v", c.name, got, c.want)
		}
	}
	// One subscription is one rule: a filter spanning two rules is refused.
	cl := Client{Subscribe: []Rule{game, alerts}}
	if cl.mayRead([]string{"dev.bnei.fleet.session.", "dev.bnei.alert."}, []string{"fleet/client/game/*"}) {
		t.Error("a filter across two rules was admitted")
	}
}

func TestParseClients(t *testing.T) {
	ok := `{"bridge-core": {"privileged": true, "publish_types": ["dev.bnei.agent."], "publish_subjects": [""],
		"subscribe": [{"types": ["dev.bnei.github."], "subjects": [""]}]}}`
	cs, err := ParseClients(ok)
	if err != nil {
		t.Fatal(err)
	}
	if c := cs["bridge-core"]; c.Name != "bridge-core" || c.Kind != "machine" {
		t.Fatalf("parsed %+v", c)
	}
	bad := map[string]string{
		"privileged app":          `{"bridge-game": {"privileged": true}}`,
		"slash in name":           `{"a/b": {}}`,
		"type prefix without dot": `{"bridge-game": {"publish_types": ["dev.bnei.game"]}}`,
		"rule without subjects":   `{"bridge-game": {"subscribe": [{"types": ["dev.bnei.game."]}]}}`,
		"rule without types":      `{"bridge-game": {"subscribe": [{"subjects": [""]}]}}`,
		"rule type without dot":   `{"bridge-game": {"subscribe": [{"types": ["dev"], "subjects": [""]}]}}`,
		"unknown kind":            `{"bridge-game": {"kind": "root"}}`,
		"old bearer field":        `{"bridge-game": {"token_sha256": "00"}}`,
	}
	for name, js := range bad {
		if _, err := ParseClients(js); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "old bearer field" && !strings.Contains(err.Error(), "token_sha256") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
