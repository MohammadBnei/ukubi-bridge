package bus

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// With no contract loaded nothing is flagged (consumers drop flagged events); once loaded, a type
// outside it is, and blessing it unflags it at the next delivery.
func TestFlags(t *testing.T) {
	e := event.Event{Type: "dev.bnei.new.thing"}
	if flags(e) != nil {
		t.Fatal("no contract loaded: no flag")
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	write := func(types string) {
		if err := os.WriteFile(path, []byte("types:\n"+types), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := contract.Load(path); err != nil {
			t.Fatal(err)
		}
	}
	write("  - {type: dev.bnei.other.x}\n")
	if !slices.Equal(flags(e), []string{"uncontracted"}) {
		t.Fatalf("flags %v", flags(e))
	}
	if got := toProto(e, false).GetFlags(); !slices.Equal(got, []string{"uncontracted"}) {
		t.Fatalf("on the wire: %v", got)
	}
	write("  - {type: dev.bnei.other.x}\n  - {type: dev.bnei.new.thing}\n")
	if flags(e) != nil {
		t.Fatal("blessed type still flagged")
	}
}
