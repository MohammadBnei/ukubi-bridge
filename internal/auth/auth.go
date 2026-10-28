// Package auth checks the authentik access tokens API clients present
// (infra-bootstrap ADR-0066 §1): RS256 only, signed by a pinned certificate,
// for this bridge's issuer and client id, not about to expire.
package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// skew is the leeway for nbf and iat only. exp gets none: a stream is bounded
// by exp, so a token accepted past it would end its stream before it began.
const skew = time.Minute

// ErrNoKey: no certificate is pinned yet, so every token is refused.
var ErrNoKey = errors.New("no signing certificate pinned (BRIDGE_OIDC_CERT)")

// ErrExpired is a token past its exp: the client refreshes it.
var ErrExpired = errors.New("token: expired")

// Verifier checks tokens against pinned keys. The keys are the trust anchor:
// a JWKS fetched over the pod network could be spoofed, so Watch only compares.
type Verifier struct {
	Issuer   string
	ClientID string
	keys     []*rsa.PublicKey
	now      func() time.Time
}

// New pins the RSA keys of the certificates in certPEM (one or more, for a
// rotation). An empty certPEM gives a Verifier that refuses every token.
func New(issuer, clientID, certPEM string) (*Verifier, error) {
	v := &Verifier{Issuer: issuer, ClientID: clientID, now: time.Now}
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			if len(bytes.TrimSpace(rest)) > 0 {
				return nil, errors.New("BRIDGE_OIDC_CERT: unreadable data after the last certificate")
			}
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("BRIDGE_OIDC_CERT: unexpected PEM block %q", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("BRIDGE_OIDC_CERT: %w", err)
		}
		k, ok := c.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("BRIDGE_OIDC_CERT: not an RSA key (RS256 only)")
		}
		v.keys = append(v.keys, k)
	}
	if len(v.keys) == 0 && certPEM != "" {
		return nil, errors.New("BRIDGE_OIDC_CERT is set but holds no PEM certificate")
	}
	if len(v.keys) > 0 && (issuer == "" || clientID == "") {
		return nil, errors.New("BRIDGE_OIDC_ISSUER and BRIDGE_OIDC_CLIENT_ID are required with a certificate")
	}
	return v, nil
}

// Pinned reports whether a certificate is pinned; without one every token is refused.
func (v *Verifier) Pinned() bool { return len(v.keys) > 0 }

type claims struct {
	jwt.Claims
	AZP string `json:"azp"`
}

// Verify returns the token's subject (the authentik username) and expiry.
func (v *Verifier) Verify(raw string) (string, time.Time, error) {
	if len(v.keys) == 0 {
		return "", time.Time{}, ErrNoKey
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token: %w", err)
	}
	var c claims
	verified := false
	for _, k := range v.keys {
		err := tok.Claims(k, &c)
		if err == nil {
			verified = true
			break
		}
		if !errors.Is(err, jose.ErrCryptoFailure) {
			return "", time.Time{}, fmt.Errorf("token: %w", err) // malformed header or claims
		}
	}
	if !verified {
		return "", time.Time{}, errors.New("token: signature matches no pinned key")
	}
	now := v.now()
	switch {
	case c.Issuer != v.Issuer:
		return "", time.Time{}, fmt.Errorf("token: issuer %q", c.Issuer)
	case !slices.Contains(c.Audience, v.ClientID) || c.AZP != v.ClientID:
		return "", time.Time{}, errors.New("token: not issued to this bridge")
	case c.Expiry == nil:
		return "", time.Time{}, errors.New("token: no exp")
	case !c.Expiry.Time().After(now):
		return "", time.Time{}, ErrExpired
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(skew)):
		return "", time.Time{}, errors.New("token: not valid yet")
	case c.IssuedAt != nil && c.IssuedAt.Time().After(now.Add(skew)):
		return "", time.Time{}, errors.New("token: issued in the future")
	case c.Subject == "":
		return "", time.Time{}, errors.New("token: no sub")
	}
	return c.Subject, c.Expiry.Time(), nil
}

// Watch fetches the provider's JWKS every interval and warns when none of its
// keys is pinned, which is what a certificate rotation looks like. It never
// changes what Verify trusts.
func (v *Verifier) Watch(ctx context.Context, url string, client *http.Client, every time.Duration) {
	if !v.Pinned() {
		return // nothing to compare yet
	}
	for {
		if err := v.compare(ctx, url, client); err != nil {
			slog.Warn("oidc: jwks check", "url", url, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (v *Verifier) compare(ctx context.Context, url string, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", res.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return err
	}
	for _, k := range set.Keys {
		if pub, ok := k.Key.(*rsa.PublicKey); ok && slices.ContainsFunc(v.keys, func(p *rsa.PublicKey) bool { return p.Equal(pub) }) {
			return nil
		}
	}
	return fmt.Errorf("none of the %d published keys is pinned: rotate BRIDGE_OIDC_CERT", len(set.Keys))
}
