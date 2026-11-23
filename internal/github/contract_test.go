package github

import (
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
)

// Every event/action pair the adapter accepts builds a type the event contract lists.
func TestTypesContracted(t *testing.T) {
	t.Cleanup(contract.Reset)
	if err := contract.Load("../../contract/events.yaml"); err != nil {
		t.Fatal(err)
	}
	body := `{"repository":{"full_name":"o/r"},"sender":{"login":"s"},
		"pull_request":{"number":1,"user":{"login":"u"},"head":{"repo":{"full_name":"o/r"}}},
		"issue":{"number":1,"user":{"login":"u"}},"comment":{"user":{"login":"u"}},"review":{"user":{"login":"u"}}}`
	n := 0
	for kind, actions := range allowed {
		for action := range actions {
			e, err := Normalize(policy, kind, "d", []byte(`{"action":"`+action+`",`+body[1:]), time.Now())
			if err != nil {
				t.Fatalf("%s/%s: %v", kind, action, err)
			}
			if !contract.Known(e.Type) {
				t.Errorf("%s/%s builds %s: not in contract/events.yaml", kind, action, e.Type)
			}
			n++
		}
	}
	if n != 9 {
		t.Errorf("%d event/action pairs: the check no longer sees them all", n)
	}
}
