package bus

import (
	"connectrpc.com/connect"

	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
)

// Key is one of the bridge's error keys (mountain plan/15 §4): stable, carried beside Connect's code as an ErrorKey
// detail, so a client never parses a message. The registry is closed: TestErrKeys refuses a key that is not one of
// these constants, and an error built anywhere but here.
type Key string

const (
	keyBearer        Key = "auth.bearer_required"
	keyToken         Key = "auth.token_invalid"
	keyNotClient     Key = "auth.not_a_client"
	keyNotOwned      Key = "auth.subscription_not_owned"
	keyNearExpiry    Key = "stream.token_near_expiry"
	keyExpired       Key = "stream.token_expired"
	keyGapped        Key = "stream.gapped"
	keyStore         Key = "store.unavailable"
	keyFields        Key = "publish.fields_required"
	keyType          Key = "publish.type_denied"
	keySubject       Key = "publish.subject_denied"
	keyHops          Key = "publish.hops_out_of_range"
	keyData          Key = "publish.data_not_json"
	keyActor         Key = "publish.actor_unknown"
	keyRefused       Key = "publish.refused"
	keyFilter        Key = "subscribe.filter_denied"
	keyNotInFlight   Key = "ack.not_in_flight"
	keyGapVersion    Key = "gap.version_invalid"
	keyGapUnsent     Key = "gap.version_unsent"
	keyGapStale      Key = "gap.version_stale"
	keyNoSub         Key = "replay.no_subscription"
	keyFilterRevoked Key = "replay.filter_revoked"
)

// sourcePostgres is the store: its words are the message of a keyStore or keyRefused error.
const sourcePostgres = "postgres"

// keyed is Connect's error for code with err's words, keyed: the bridge's own words.
func keyed(code connect.Code, key Key, err error) *connect.Error { return sourced(code, key, "", err) }

// sourced is keyed with the source whose words err holds.
func sourced(code connect.Code, key Key, source string, err error) *connect.Error {
	e := connect.NewError(code, err)
	if d, derr := connect.NewErrorDetail(&bridgev1.ErrorKey{Key: string(key), Source: source}); derr == nil {
		e.AddDetail(d) // ErrorKey always marshals: derr is unreachable
	}
	return e
}
