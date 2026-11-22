package forgejo

import (
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
)

// Every kind/action pair the adapter accepts builds a type the event contract lists.
func TestTypesContracted(t *testing.T) {
	if err := contract.Load("../../contract/events.yaml"); err != nil {
		t.Fatal(err)
	}
	// One payload that carries every object any kind reads.
	body := []byte(`{"repository":{"full_name":"o/r"},"sender":{"login":"s"},
		"pull_request":{"number":1,"user":{"login":"u"},"head":{"sha":"abc","repo":{"full_name":"o/r"}}},
		"issue":{"number":1,"user":{"login":"u"}},"comment":{"id":5,"user":{"login":"u"}},"review":{"id":7,"content":"x"},
		"run":{"index_in_repo":3,"repository":{"full_name":"o/r"},"trigger_user":{"login":"u"}}}`)
	n := 0
	for kind, actions := range allowed {
		for action := range actions {
			// The payload's action is the one under test, as Forgejo sends it.
			b := append([]byte(`{"action":"`+action+`",`), body[1:]...)
			e, err := Normalize(policy, kind, "d", b, time.Now())
			if err != nil {
				t.Fatalf("%s/%s: %v", kind, action, err)
			}
			if !contract.Known(e.Type) {
				t.Errorf("%s/%s builds %s: not in contract/events.yaml", kind, action, e.Type)
			}
			n++
		}
	}
	if n != 15 {
		t.Errorf("%d kind/action pairs: the check no longer sees them all", n)
	}
}
