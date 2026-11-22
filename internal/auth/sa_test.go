package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func pubPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type k8sPod struct {
	Name string `json:"name,omitempty"`
}

type k8sClaim struct {
	Namespace      string  `json:"namespace,omitempty"`
	Pod            *k8sPod `json:"pod,omitempty"`
	ServiceAccount k8sPod  `json:"serviceaccount"`
}

type saTokenClaims struct {
	jwt.Claims
	K8s *k8sClaim `json:"kubernetes.io,omitempty"`
}

func goodSA(now time.Time) saTokenClaims {
	return saTokenClaims{
		Claims: jwt.Claims{Issuer: K8sIssuer, Audience: jwt.Audience{"other", K8sAudience}, Subject: "system:serviceaccount:atlas:atlas",
			Expiry: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now)},
		K8s: &k8sClaim{Namespace: "atlas", Pod: &k8sPod{Name: "atlas-7d9f-x2"}, ServiceAccount: k8sPod{Name: "atlas"}},
	}
}

func signSA(t *testing.T, alg jose.SignatureAlgorithm, k any, c saTokenClaims) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(s).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSAVerify(t *testing.T) {
	k, other := key(t), key(t)
	v, err := NewSA(pubPEM(t, k))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v.now = func() time.Time { return now }

	id, err := v.Verify(signSA(t, jose.RS256, k, goodSA(now)))
	want := Identity{Subject: "system:serviceaccount:atlas:atlas", Expiry: now.Add(time.Hour).Truncate(time.Second),
		Namespace: "atlas", ServiceAccount: "atlas", Pod: "atlas-7d9f-x2"}
	if err != nil || id != want {
		t.Fatalf("good token: %+v %v", id, err)
	}

	mod := func(f func(*saTokenClaims)) saTokenClaims { c := goodSA(now); f(&c); return c }
	for name, c := range map[string]struct {
		raw     string
		expired bool
	}{
		"other key":    {signSA(t, jose.RS256, other, goodSA(now)), false},
		"HS256":        {signSA(t, jose.HS256, []byte(strings.Repeat("k", 32)), goodSA(now)), false},
		"RS512":        {signSA(t, jose.RS512, k, goodSA(now)), false},
		"wrong issuer": {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Issuer = "https://192.168.1.208:6443" })), false},
		"wrong aud":    {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Audience = jwt.Audience{"https://kubernetes.default.svc"} })), false},
		"no exp":       {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Expiry = nil })), false},
		"expired":      {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Expiry = jwt.NewNumericDate(now.Add(-time.Second)) })), true},
		"no iat":       {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.IssuedAt = nil })), false},
		"life over 1h": {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(-62 * time.Second)) })), false},
		"a year":       {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Expiry = jwt.NewNumericDate(now.Add(365 * 24 * time.Hour)) })), false},
		"nbf ahead":    {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(2 * time.Minute)) })), false},
		"iat ahead": {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) {
			c.IssuedAt, c.Expiry = jwt.NewNumericDate(now.Add(2*time.Minute)), jwt.NewNumericDate(now.Add(time.Hour))
		})), false},
		"no pod claim":    {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.K8s.Pod = nil })), false},
		"empty pod name":  {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.K8s.Pod = &k8sPod{} })), false},
		"no k8s claim":    {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.K8s = nil })), false},
		"sub not an SA":   {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Subject = "atlas" })), false},
		"sub extra part":  {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Subject = "system:serviceaccount:atlas:atlas:x" })), false},
		"sub vs claim ns": {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.Subject = "system:serviceaccount:agent-fleet:atlas" })), false},
		"sub vs claim sa": {signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.K8s.ServiceAccount.Name = "bridge-core" })), false},
		"garbage":         {"not.a.jwt", false},
	} {
		_, err := v.Verify(c.raw)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if errors.Is(err, ErrExpired) != c.expired {
			t.Errorf("%s: %v, expired %v", name, err, c.expired)
		}
	}
	// The bound itself: exactly an hour plus the minute of skew is fine.
	if _, err := v.Verify(signSA(t, jose.RS256, k, mod(func(c *saTokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(-60 * time.Second)) }))); err != nil {
		t.Errorf("life of 1h1m: %v", err)
	}
}

func TestNewSA(t *testing.T) {
	for _, blank := range []string{"", "\n", "  \n\t\n"} { // unset, or a helm block left empty
		v, err := NewSA(blank)
		if err != nil || v.Pinned() {
			t.Fatalf("%q: %v", blank, err)
		}
	}
	v, err := NewSA("")
	if err != nil {
		t.Fatalf("NewSA(\"\"): %v", err)
	}
	if _, err := v.Verify(signSA(t, jose.RS256, key(t), goodSA(time.Now()))); err != ErrNoSAKey {
		t.Fatalf("got %v, want ErrNoSAKey", err)
	}
	k := key(t)
	for name, in := range map[string]string{
		"not PEM":     "-----BEGIN PUBLIC KEY-----\\nMIIB...",
		"certificate": certPEM(t, k),
		"truncated":   pubPEM(t, k) + pubPEM(t, k)[:60],
	} {
		if _, err := NewSA(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, b := key(t), key(t)
	v, err = NewSA(pubPEM(t, a) + pubPEM(t, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []*rsa.PrivateKey{a, b} {
		if _, err := v.Verify(signSA(t, jose.RS256, k, goodSA(time.Now()))); err != nil {
			t.Errorf("rotation: %v", err)
		}
	}
}

// TestTokens: the issuer picks the verifier, and each issuer's token verifies with its own keys only.
func TestTokens(t *testing.T) {
	ak, sk := key(t), key(t)
	oidc, err := New(iss, aud, certPEM(t, ak))
	if err != nil {
		t.Fatal(err)
	}
	sa, err := NewSA(pubPEM(t, sk))
	if err != nil {
		t.Fatal(err)
	}
	tk := Tokens{OIDC: oidc, SA: sa}
	now := time.Now()

	id, err := tk.Verify(sign(t, jose.RS256, ak, good(now)))
	if err != nil || id.Subject != "bridge-core" || id.ServiceAccount != "" || id.Pod != "" {
		t.Fatalf("authentik token: %+v %v", id, err)
	}
	id, err = tk.Verify(signSA(t, jose.RS256, sk, goodSA(now)))
	if err != nil || id.Namespace != "atlas" || id.ServiceAccount != "atlas" || id.Pod != "atlas-7d9f-x2" {
		t.Fatalf("service account token: %+v %v", id, err)
	}
	// Crossed keys: each claims the other's issuer but is signed by the wrong anchor.
	if _, err := tk.Verify(signSA(t, jose.RS256, ak, goodSA(now))); err == nil {
		t.Error("an SA token signed by authentik's key was accepted")
	}
	if _, err := tk.Verify(sign(t, jose.RS256, sk, good(now))); err == nil {
		t.Error("an authentik token signed by the cluster key was accepted")
	}
	if _, err := tk.Verify("not.a.jwt"); err == nil {
		t.Error("garbage accepted")
	}
	// The SA verifier off: an SA token is refused with its own no-key error, authentik still works.
	off, _ := NewSA("")
	tk.SA = off
	if _, err := tk.Verify(signSA(t, jose.RS256, sk, goodSA(now))); !errors.Is(err, ErrNoSAKey) {
		t.Errorf("SA off: %v, want ErrNoSAKey", err)
	}
	if _, err := tk.Verify(sign(t, jose.RS256, ak, good(now))); err != nil {
		t.Errorf("SA off, authentik token: %v", err)
	}
}

// TestHelmSAKey: the key shipped in helm/values.yaml parses and pins one RSA key.
func TestHelmSAKey(t *testing.T) {
	b, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)name: BRIDGE_K8S_SA_KEY\n\s+value: \|\n((?:\s{6}.*\n)+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("BRIDGE_K8S_SA_KEY block not found")
	}
	var lines []string
	for _, l := range strings.Split(string(m[1]), "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	v, err := NewSA(strings.Join(lines, "\n"))
	if err != nil || len(v.keys) != 1 {
		t.Fatalf("%v, %d keys", err, len(v.keys))
	}
}
