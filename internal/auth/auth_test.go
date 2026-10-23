package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const iss, aud = "https://authentik.example/application/o/ukubi-bridge-api/", "ukubi-bridge-api"

func certPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type tokenClaims struct {
	jwt.Claims
	AZP string `json:"azp,omitempty"`
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, k any, c tokenClaims) string {
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

func good(now time.Time) tokenClaims {
	return tokenClaims{Claims: jwt.Claims{Issuer: iss, Audience: jwt.Audience{aud}, Subject: "bridge-core",
		Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute)), IssuedAt: jwt.NewNumericDate(now)}, AZP: aud}
}

func TestVerify(t *testing.T) {
	k, other := key(t), key(t)
	v, err := New(iss, aud, certPEM(t, k))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v.now = func() time.Time { return now }

	sub, exp, err := v.Verify(sign(t, jose.RS256, k, good(now)))
	if err != nil || sub != "bridge-core" || !exp.Equal(now.Add(10*time.Minute).Truncate(time.Second)) {
		t.Fatalf("good token: sub %q exp %v err %v", sub, exp, err)
	}

	mod := func(f func(*tokenClaims)) tokenClaims { c := good(now); f(&c); return c }
	cases := map[string]string{
		"other key":    sign(t, jose.RS256, other, good(now)),
		"HS256":        sign(t, jose.HS256, []byte(strings.Repeat("k", 32)), good(now)),
		"wrong issuer": sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Issuer = "https://authentik.example/application/o/mountain/" })),
		"wrong aud":    sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Audience = jwt.Audience{"mountain"} })),
		"wrong azp":    sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.AZP = "mountain" })),
		"no azp":       sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.AZP = "" })),
		"no exp":       sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Expiry = nil })),
		"expired":      sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Expiry = jwt.NewNumericDate(now.Add(-time.Second)) })),
		"under 15 s":   sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Expiry = jwt.NewNumericDate(now.Add(10 * time.Second)) })),
		"nbf ahead":    sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.NotBefore = jwt.NewNumericDate(now.Add(2 * time.Minute)) })),
		"iat ahead":    sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(2 * time.Minute)) })),
		"no sub":       sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.Subject = "" })),
		"garbage":      "not.a.jwt",
		"alg none":     unsigned(t, good(now)),
	}
	for name, raw := range cases {
		if _, _, err := v.Verify(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Skew within a minute on nbf/iat is fine.
	if _, _, err := v.Verify(sign(t, jose.RS256, k, mod(func(c *tokenClaims) { c.IssuedAt = jwt.NewNumericDate(now.Add(30 * time.Second)) }))); err != nil {
		t.Errorf("iat 30 s ahead: %v", err)
	}
}

func unsigned(t *testing.T, c tokenClaims) string {
	t.Helper()
	b, _ := json.Marshal(c)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(b) + "."
}

func TestNoCertRefusesAll(t *testing.T) {
	v, err := New("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	k := key(t)
	if _, _, err := v.Verify(sign(t, jose.RS256, k, good(time.Now()))); err != ErrNoKey {
		t.Fatalf("got %v, want ErrNoKey", err)
	}
}

func TestRotationPinsTwo(t *testing.T) {
	a, b := key(t), key(t)
	v, err := New(iss, aud, certPEM(t, a)+certPEM(t, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []*rsa.PrivateKey{a, b} {
		if _, _, err := v.Verify(sign(t, jose.RS256, k, good(time.Now()))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCompare(t *testing.T) {
	pinned, other := key(t), key(t)
	v, _ := New(iss, aud, certPEM(t, pinned))
	publish := &pinned.PublicKey
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: publish, Algorithm: "RS256", Use: "sig"}}})
	}))
	defer srv.Close()
	if err := v.compare(context.Background(), srv.URL, srv.Client()); err != nil {
		t.Fatalf("pinned key published: %v", err)
	}
	publish = &other.PublicKey
	if err := v.compare(context.Background(), srv.URL, srv.Client()); err == nil {
		t.Fatal("a rotation went unnoticed")
	}
}
