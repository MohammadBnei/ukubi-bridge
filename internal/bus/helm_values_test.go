package bus

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
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
	core, game, push, atlas, kwatch := cs["bridge-core"], cs["bridge-game"], cs["bridge-push"], cs["bridge-atlas"], cs["bridge-kwatch"]
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
	// Core hands an event back to its own thread (PublishEvent): forge/ since
	// P4.4, github/ kept while a rollback to the GitHub route is possible.
	for _, sub := range []string{"forge/o/r/pr/1", "github/o/r/pr/1"} {
		if !slices.ContainsFunc(core.PublishSubjects, func(pre string) bool { return strings.HasPrefix(sub, pre) }) {
			t.Errorf("bridge-core cannot publish on %s", sub)
		}
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
	// The k8s watch adapter writes deploy and k8s events on their own threads only, and reads nothing.
	if len(kwatch.Subscribe) != 0 || !slices.Equal(kwatch.PublishTypes, []string{"dev.bnei.deploy.", "dev.bnei.k8s."}) ||
		!slices.Equal(kwatch.PublishSubjects, []string{"argocd/", "k8s/"}) {
		t.Errorf("bridge-kwatch: %+v", kwatch)
	}
}

// The contract ConfigMap in helm/values.yaml is contract/events.yaml byte for byte, mounted where
// BRIDGE_CONTRACT_FILE reads it.
func TestHelmContract(t *testing.T) {
	b, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ExtraManifests []string `json:"extraManifests"`
		Env            []struct{ Name, Value string }
		Mounts         []struct{ Name, MountPath, SubPath string } `json:"extraVolumeMounts"`
		Volumes        []struct {
			Name      string
			ConfigMap struct {
				Name     string
				Optional bool
			}
		} `json:"extraVolumes"`
	}
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Kind     string
		Metadata struct{ Name string }
		Data     map[string]string
	}
	found := false
	for _, m := range v.ExtraManifests {
		if err := yaml.Unmarshal([]byte(m), &cm); err == nil && cm.Kind == "ConfigMap" && cm.Metadata.Name == "ukubi-bridge-contract" {
			found = true
		}
	}
	if !found {
		t.Fatal("ConfigMap ukubi-bridge-contract not found in extraManifests")
	}
	want, err := os.ReadFile("../../contract/events.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(want), "{{") {
		t.Error(`the chart runs extraManifests through tpl: "{{" would be rendered`)
	}
	if !slices.ContainsFunc(v.Volumes, func(x struct {
		Name      string
		ConfigMap struct {
			Name     string
			Optional bool
		}
	}) bool {
		return x.Name == "contract" && x.ConfigMap.Name == "ukubi-bridge-contract" && x.ConfigMap.Optional
	}) {
		t.Error("volume contract must be the optional ConfigMap ukubi-bridge-contract")
	}
	if cm.Data["events.yaml"] != string(want) {
		t.Error("helm/values.yaml's contract differs from contract/events.yaml: copy it in, indented")
	}
	file := ""
	for _, e := range v.Env {
		if e.Name == "BRIDGE_CONTRACT_FILE" {
			file = e.Value
		}
	}
	if !slices.ContainsFunc(v.Mounts, func(m struct{ Name, MountPath, SubPath string }) bool {
		return m.Name == "contract" && m.SubPath == "" && file == m.MountPath+"/events.yaml" // subPath would break hot reload
	}) {
		t.Errorf("BRIDGE_CONTRACT_FILE %q is not events.yaml in the contract mount", file)
	}
}

// Every type prefix a client may publish has a contract entry under it, so its events are not flagged
// on day one (and a consumer that skips flags does not drop them).
func TestClientGrantsContracted(t *testing.T) {
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
	raw, err := os.ReadFile("../../contract/events.yaml")
	if err != nil {
		t.Fatal(err)
	}
	es, err := contract.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range cs {
		for _, p := range c.PublishTypes {
			if !slices.ContainsFunc(es, func(e contract.Entry) bool { return strings.HasPrefix(strings.TrimSuffix(e.Type, "*"), p) }) {
				t.Errorf("%s may publish %s but no contract entry is under it", name, p)
			}
		}
	}
}
