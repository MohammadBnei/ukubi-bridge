package bus

import (
	"errors"

	"connectrpc.com/connect"
	"github.com/MohammadBnei/ukubi-go/errs"
	"github.com/MohammadBnei/ukubi-go/errs/connectkeys"
	errorsv1 "github.com/MohammadBnei/ukubi-go/proto/gen/go/ukubi/errors/v1"

	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
)

// Key is one of the bridge's error keys (mountain plan/15 §4): stable, carried beside Connect's code as an ErrorKey
// detail, so a client never parses a message. The registry is closed: TestErrKeys refuses a key that is not one of
// these constants (or of tokenKey's), an error built with Connect anywhere but here, and any use of keys or of
// ukubi-go's errs and connectkeys outside this file. withInterceptors keys whatever a handler returns unkeyed as
// keyInternal (connectkeys.KeyInternal), so every error a handler returns carries one.
type Key = errs.Key

const (
	keyBearer        Key = "auth.bearer_required"
	keyToken         Key = "auth.token_invalid"
	keyNoKey         Key = "auth.no_key_pinned"
	keyExpired       Key = "auth.token_expired"
	keyNotClient     Key = "auth.not_a_client"
	keyNotOwned      Key = "auth.subscription_not_owned"
	keyNearExpiry    Key = "stream.token_near_expiry"
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
	keyNotInFlight   Key = "delivery.not_in_flight"
	keyGapVersion    Key = "gap.version_invalid"
	keyGapUnsent     Key = "gap.version_unsent"
	keyGapStale      Key = "gap.version_stale"
	keyNoSub         Key = "replay.no_subscription"
	keyFilterRevoked Key = "replay.filter_revoked"
	keyInternal      Key = "server.internal"
)

// sourceStore is the store (pgx and Postgres): its words are the message of a keyStore or keyRefused error.
const sourceStore = "store"

// tokenKey is the key for a token the verifier refused: unpinned (the bridge's configuration), expired (refresh it),
// or otherwise invalid.
func tokenKey(err error) Key {
	switch {
	case errors.Is(err, auth.ErrNoKey):
		return keyNoKey
	case errors.Is(err, auth.ErrExpired):
		return keyExpired
	}
	return keyToken
}

// keys puts every key as two details with the same bytes: bridge.v1.ErrorKey, the bridge's detail since #12, first, then
// ukubi.errors.v1.ErrorKey (standard §6). Its value never changes after New.
var keys = connectkeys.New(&bridgev1.ErrorKey{}, &errorsv1.ErrorKey{})

// keyed is Connect's error for code with err's words, keyed: the bridge's own words.
func keyed(code connect.Code, key Key, err error) *connect.Error { return keys.Connect(code, key, err) }

// sourced is keyed with the source whose words err holds.
func sourced(code connect.Code, key Key, source string, err error) *connect.Error {
	return keys.Sourced(code, key, source, err)
}

// withInterceptors is the API handler's option: ics, inside connectkeys' fallback, which keys anything a handler or
// any of ics returns without a key as keyInternal on a copy, keeping its code and words (a context error's own code).
// An unreadable unary request or an unknown procedure carries no key: Connect refuses it before the handler runs. A
// stream's unreadable request is read inside the handler chain, so it is keyed server.internal, with Connect's code.
func withInterceptors(ics ...connect.Interceptor) connect.HandlerOption {
	return keys.WithInterceptors(ics...)
}
