// Package contract is the bus's event contract (contract/events.yaml), read at
// runtime: a knowledge input, so it never stops the bridge. Failures are logged
// at WARN ("event contract not loaded" / "not reloaded"), which the chart's Loki rules alert on. A bad or missing
// file keeps the last good copy; if none ever loaded, nothing is flagged.
package contract

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"sigs.k8s.io/yaml"
)

// Entry is one shared type. A Type ending in ".*" is a prefix.
type Entry struct {
	Type     string   `json:"type"`
	Subject  string   `json:"subject"`
	CEID     string   `json:"ce_id"`
	CEIDKind string   `json:"ce_id_kind"` // fact | transport
	Producer string   `json:"producer"`
	Status   string   `json:"status"` // "" or retiring
	Note     string   `json:"note"`
	Trust    []string `json:"trust"`
}

type file struct {
	Envelope map[string]string `json:"envelope"`
	Types    []Entry           `json:"types"`
}

type index struct {
	exact    map[string]bool
	prefixes []string
}

var cur atomic.Pointer[index]

// Parse reads a contract file's types. Unknown fields are ignored: the file
// ships through ArgoCD before the image that understands a new field, and an
// old image must keep accepting it (ParseStrict is the CI check).
func Parse(b []byte) ([]Entry, error) {
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return check(f)
}

// ParseStrict is Parse that also rejects unknown fields and values outside the
// documented enums. For tests only.
func ParseStrict(b []byte) ([]Entry, error) {
	var f file
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, err
	}
	for _, e := range f.Types {
		if e.CEID == "" || (e.CEIDKind != "fact" && e.CEIDKind != "transport" && e.CEIDKind != "storage") ||
			(e.Status != "" && e.Status != "retiring") {
			return nil, fmt.Errorf("type %q: ce_id, ce_id_kind (fact|transport|storage) or status (retiring) is wrong", e.Type)
		}
	}
	return check(f)
}

func check(f file) ([]Entry, error) {
	if len(f.Types) == 0 {
		return nil, fmt.Errorf("no types")
	}
	seen := map[string]bool{}
	for _, e := range f.Types {
		if !strings.HasPrefix(e.Type, "dev.bnei.") || seen[e.Type] {
			return nil, fmt.Errorf("bad or repeated type %q", e.Type)
		}
		// A prefix is "<a>.<b>.<c>.*": at least three segments, so one entry cannot contract the whole bus.
		if i := strings.Index(e.Type, "*"); i >= 0 && (i != len(e.Type)-1 || e.Type[i-1] != '.' || strings.Count(e.Type[:i], ".") < 3) {
			return nil, fmt.Errorf("bad prefix %q: want dev.bnei.<domain>.*", e.Type)
		}
		seen[e.Type] = true
	}
	return f.Types, nil
}

// Load reads path and, if it parses, makes it the current contract.
func Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	es, err := Parse(b)
	if err != nil {
		return err
	}
	ix := &index{exact: map[string]bool{}}
	for _, e := range es {
		if p, ok := strings.CutSuffix(e.Type, "*"); ok {
			ix.prefixes = append(ix.prefixes, p)
		} else {
			ix.exact[e.Type] = true
		}
	}
	cur.Store(ix)
	return nil
}

// Flags returns the flags an event of type t carries: "uncontracted" when a
// contract has loaded and lacks t. Nil while none has loaded.
func Flags(t string) []string {
	if !Loaded() || Known(t) {
		return nil
	}
	return []string{"uncontracted"}
}

// Reset forgets the loaded contract. For tests, which t.Cleanup it after a Load.
func Reset() { cur.Store(nil) }

// Loaded reports whether any contract has ever loaded.
func Loaded() bool { return cur.Load() != nil }

// Known reports whether t is in the current contract. False while none loaded:
// callers flag only when Loaded.
func Known(t string) bool {
	ix := cur.Load()
	if ix == nil {
		return false
	}
	if ix.exact[t] {
		return true
	}
	for _, p := range ix.prefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// Run loads path now and every interval until ctx ends. A failure keeps the
// last good copy and logs a warning; with none loaded yet the warning says
// nothing is flagged.
func Run(ctx context.Context, path string, every time.Duration) {
	if path == "" {
		slog.Warn("event contract not loaded: BRIDGE_CONTRACT_FILE is unset (not configured); no event is flagged uncontracted")
		return
	}
	for {
		if err := Load(path); err != nil {
			if Loaded() {
				slog.Warn("event contract not reloaded", "file", path, "kept", "the last good copy", "err", err)
			} else {
				slog.Warn("event contract not loaded", "file", path, "flagging", "off", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
