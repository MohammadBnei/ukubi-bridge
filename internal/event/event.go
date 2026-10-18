// Package event is the bus envelope: CloudEvents 1.0 attributes plus the
// extensions ADR-0059 defines. The proto form (for the gRPC API) maps 1:1.
package event

import (
	"encoding/json"
	"time"
)

// Actor kinds. Trust is decided separately: a human can be untrusted.
const (
	ActorHuman   = "human"
	ActorBot     = "bot"
	ActorAgent   = "agent"
	ActorMachine = "machine"
)

type Event struct {
	Seq int64 // log position (events.id); assigned by the store, zero before insert

	// CloudEvents required attributes.
	ID     string // ce_id: unique per Source (X-GitHub-Delivery for GitHub)
	Source string // e.g. "github.com/MohammadBnei/editable-blog"
	Type   string // e.g. "dev.bnei.github.pull_request.opened"
	// Subject is the thread key, e.g. "github/MohammadBnei/editable-blog/pr/42".
	Subject string
	Time    time.Time
	Data    json.RawMessage

	// Extensions.
	Actor       string // ActorHuman | ActorBot | ActorAgent | ActorMachine
	ActorLogin  string // who caused it (GitHub login, empty for machine sources)
	Trusted     bool   // may open a new thread / wake a session (ADR-0071 §6)
	Owner       string // routed definition; set by the dispatcher, empty at ingest
	Hops        int
	CausationID string
	Replayed    bool
}
