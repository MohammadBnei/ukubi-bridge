package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The cluster's service account tokens (plan M3): projected for this audience,
// issued by the Talos cluster's API server. ponytail: the issuer is a
// constant; make it a setting if a second cluster ever calls the bridge.
const (
	K8sIssuer   = "https://192.168.1.211:6443"
	K8sAudience = "ukubi-bridge"
	// maxLife bounds exp-iat: a projected token asks for at most an hour. A
	// longer one is a legacy or extended token, which a stolen pod could keep.
	maxLife = time.Hour + skew
)

// ErrNoSAKey: no service account key is pinned, so every cluster token is refused.
var ErrNoSAKey = errors.New("no service account key pinned (BRIDGE_K8S_SA_KEY)")

// Identity is who a verified token names. Namespace, ServiceAccount and Pod
// are set for a service account token only.
type Identity struct {
	Subject                        string // the authentik username, or system:serviceaccount:<ns>:<sa>
	Expiry                         time.Time
	Namespace, ServiceAccount, Pod string
}

// SAVerifier checks projected service account tokens against the pinned
// cluster key(s): the trust anchor, as for authentik (Watch only compares).
type SAVerifier struct {
	keys []*rsa.PublicKey
	now  func() time.Time
}

// NewSA pins the RSA public keys (PEM "PUBLIC KEY" blocks, one or more for a
// rotation) in keyPEM. An empty keyPEM gives a verifier that refuses every token.
func NewSA(keyPEM string) (*SAVerifier, error) {
	v := &SAVerifier{now: time.Now}
	rest := []byte(keyPEM)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			if len(bytes.TrimSpace(rest)) > 0 {
				return nil, errors.New("BRIDGE_K8S_SA_KEY: unreadable data after the last key")
			}
			break
		}
		if b.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("BRIDGE_K8S_SA_KEY: unexpected PEM block %q", b.Type)
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("BRIDGE_K8S_SA_KEY: %w", err)
		}
		rk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("BRIDGE_K8S_SA_KEY: not an RSA key (RS256 only)")
		}
		v.keys = append(v.keys, rk)
	}
	if len(v.keys) == 0 && strings.TrimSpace(keyPEM) != "" { // a blank value (an empty helm block) is unset
		return nil, errors.New("BRIDGE_K8S_SA_KEY is set but holds no PEM public key")
	}
	return v, nil
}

// Pinned reports whether a key is pinned; without one every cluster token is refused.
func (v *SAVerifier) Pinned() bool { return len(v.keys) > 0 }

type saClaims struct {
	jwt.Claims
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// Verify checks a projected token in full and returns its pod identity.
func (v *SAVerifier) Verify(raw string) (Identity, error) {
	if len(v.keys) == 0 {
		return Identity{}, ErrNoSAKey
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Identity{}, fmt.Errorf("token: %w", err)
	}
	var c saClaims
	verified := false
	for _, k := range v.keys {
		err := tok.Claims(k, &c)
		if err == nil {
			verified = true
			break
		}
		if !errors.Is(err, jose.ErrCryptoFailure) {
			return Identity{}, fmt.Errorf("token: %w", err)
		}
	}
	if !verified {
		return Identity{}, errors.New("token: signature matches no pinned service account key")
	}
	now := v.now()
	rest, isSA := strings.CutPrefix(c.Subject, "system:serviceaccount:")
	ns, sa, _ := strings.Cut(rest, ":")
	subOK := isSA && ns != "" && sa != "" && !strings.Contains(sa, ":")
	switch {
	case c.Issuer != K8sIssuer:
		return Identity{}, fmt.Errorf("token: issuer %q", c.Issuer)
	case !slices.Contains(c.Audience, K8sAudience):
		return Identity{}, errors.New("token: not issued to this bridge")
	case c.Expiry == nil:
		return Identity{}, errors.New("token: no exp")
	case !c.Expiry.Time().After(now):
		return Identity{}, ErrExpired
	case c.IssuedAt == nil:
		return Identity{}, errors.New("token: no iat")
	case c.Expiry.Time().Sub(c.IssuedAt.Time()) > maxLife:
		return Identity{}, errors.New("token: lifetime over 1h (project it with expirationSeconds <= 3600)")
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(skew)):
		return Identity{}, errors.New("token: not valid yet")
	case c.IssuedAt.Time().After(now.Add(skew)):
		return Identity{}, errors.New("token: issued in the future")
	case !subOK:
		return Identity{}, fmt.Errorf("token: sub %q is not a service account", c.Subject)
	case c.K8s.Namespace != ns || c.K8s.ServiceAccount.Name != sa:
		return Identity{}, errors.New("token: kubernetes.io claim does not match sub")
	case c.K8s.Pod.Name == "":
		return Identity{}, errors.New("token: no kubernetes.io pod claim (not a pod-bound token)")
	}
	return Identity{Subject: c.Subject, Expiry: c.Expiry.Time(), Namespace: ns, ServiceAccount: sa, Pod: c.K8s.Pod.Name}, nil
}

// Watch compares the cluster's JWKS with the pinned keys every interval and
// warns when any published key is not pinned (a signing-key rotation or a
// cluster rebuild: re-pin BRIDGE_K8S_SA_KEY).
func (v *SAVerifier) Watch(ctx context.Context, url string, client *http.Client, every time.Duration) {
	watch(ctx, "k8s-sa", url, client, every, v.keys, "BRIDGE_K8S_SA_KEY", true)
}

// Tokens is the API's verifier: authentik and the cluster side by side.
type Tokens struct {
	OIDC *Verifier
	SA   *SAVerifier
}

// Verify picks the verifier by the token's issuer, read unverified, then
// verifies in full with that one only: an issuer never reaches the other's keys.
func (t Tokens) Verify(raw string) (Identity, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Identity{}, fmt.Errorf("token: %w", err)
	}
	var c jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&c); err != nil {
		return Identity{}, fmt.Errorf("token: %w", err)
	}
	if c.Issuer == K8sIssuer {
		return t.SA.Verify(raw)
	}
	sub, exp, err := t.OIDC.Verify(raw)
	return Identity{Subject: sub, Expiry: exp}, err
}
