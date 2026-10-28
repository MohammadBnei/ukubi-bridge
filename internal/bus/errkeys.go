package bus

import (
	"context"
	"errors"
	"os"

	"connectrpc.com/connect"

	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
)

// Key is one of the bridge's error keys (mountain plan/15 §4): stable, carried beside Connect's code as an ErrorKey
// detail, so a client never parses a message. The registry is closed: TestErrKeys refuses a key that is not one of
// these constants (or of tokenKey's), and an error built with Connect anywhere but here. keyAll keys whatever a
// handler returns unkeyed as keyInternal, so every error a handler returns carries one.
type Key string

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

// keyed is Connect's error for code with err's words, keyed: the bridge's own words.
func keyed(code connect.Code, key Key, err error) *connect.Error { return sourced(code, key, "", err) }

// sourced is keyed with the source whose words err holds.
func sourced(code connect.Code, key Key, source string, err error) *connect.Error {
	e := connect.NewError(code, err)
	addKey(e, key, source)
	return e
}

func addKey(e *connect.Error, key Key, source string) {
	d, err := connect.NewErrorDetail(&bridgev1.ErrorKey{Key: string(key), Source: source})
	if err != nil {
		panic(err) // a two-string message always marshals
	}
	e.AddDetail(d)
}

// hasKey: err is a Connect error that already carries an ErrorKey.
func hasKey(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return false
	}
	for _, d := range ce.Details() {
		if d.Type() == "bridge.v1.ErrorKey" {
			return true
		}
	}
	return false
}

// keyAll keys an error a handler returns without one (a raw Send failure, a path that forgot) as keyInternal,
// keeping its code and words, on a copy (the handler's own error is never changed): every error a handler returns
// carries a key. Errors Connect raises before the handler runs (an unreadable body, an unknown procedure) carry none.
type keyAll struct{}

func (keyAll) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		return res, withKey(err)
	}
}

func (keyAll) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (keyAll) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error { return withKey(next(ctx, conn)) }
}

func withKey(err error) error {
	if err == nil || hasKey(err) {
		return err
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		e := connect.NewError(plainCode(err), err) // a plain error: the code Connect would send for it
		addKey(e, keyInternal, "")
		return e
	}
	// A copy, never ce itself: a handler may return a shared sentinel, which adding to would race across requests and
	// stay keyed for in-process callers. Meta() makes the map on its first call, a write: so read a struct copy of ce,
	// whose Meta() makes it on the copy only.
	src := *ce
	e := connect.NewError(src.Code(), src.Unwrap())
	for _, d := range src.Details() {
		e.AddDetail(d)
	}
	for k, v := range src.Meta() {
		e.Meta()[k] = append([]string(nil), v...)
	}
	addKey(e, keyInternal, "")
	return e
}

// plainCode is the code Connect sends for a plain error (its toWire, wrapIfContextError): a context error's own,
// wrapped or not, else Unknown.
func plainCode(err error) connect.Code {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return connect.CodeDeadlineExceeded
	}
	return connect.CodeUnknown
}
