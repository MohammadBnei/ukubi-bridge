package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func envOf(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

func keyPEM(t *testing.T) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// TestConfigDefaults: only the secret set, every other setting takes its default.
func TestConfigDefaults(t *testing.T) {
	c, err := load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s"}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{WebhookSecret: "s", Trusted: map[string]bool{}, Agents: map[string]bool{}, Retention: 720 * time.Hour, Port: "8080"}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("%+v, want %+v", c, want)
	}
}

// TestConfigEnv: each variable reaches its field.
func TestConfigEnv(t *testing.T) {
	key := keyPEM(t)
	c, err := load(envOf(map[string]string{
		"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_CLIENTS": "x", "BRIDGE_API_CLIENTS": "{}",
		"BRIDGE_OIDC_ISSUER": "i", "BRIDGE_OIDC_CLIENT_ID": "c", "BRIDGE_OIDC_CERT": "pem", "BRIDGE_OIDC_JWKS_URL": "j",
		"BRIDGE_DATABASE_URL": "db", "BRIDGE_TRUSTED_LOGINS": " a, b,,", "BRIDGE_AGENT_LOGINS": "c",
		"BRIDGE_ALERT_TOKEN": "t", "BRIDGE_RETENTION": "48h", "PORT": "9", "BRIDGE_GITHUB_APP_ID": "7",
		"BRIDGE_GITHUB_APP_PRIVATE_KEY": key, "BRIDGE_RECONCILE_LOOKBACK": "1h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.App == nil || c.App.ID != "7" || c.App.Key == nil || c.App.Lookback != time.Hour {
		t.Fatalf("app: %+v", c.App)
	}
	c.App = nil
	want := Config{WebhookSecret: "s", LegacyClients: true, APIClients: "{}", OIDC: OIDCConfig{"i", "c", "pem", "j"},
		DatabaseURL: "db", Trusted: map[string]bool{"a": true, "b": true}, Agents: map[string]bool{"c": true},
		AlertToken: "t", Retention: 48 * time.Hour, Port: "9"}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("%+v, want %+v", c, want)
	}
}

// TestConfigApp: the reconcile loop needs both the App's id and key; the lookback is read only with them.
func TestConfigApp(t *testing.T) {
	key := keyPEM(t)
	for _, c := range []struct {
		name     string
		env      map[string]string
		lookback time.Duration // 0: no App
	}{
		{"none", nil, 0},
		{"id only", map[string]string{"BRIDGE_GITHUB_APP_ID": "7"}, 0},
		{"key only", map[string]string{"BRIDGE_GITHUB_APP_PRIVATE_KEY": key}, 0},
		{"a bad lookback without the App", map[string]string{"BRIDGE_RECONCILE_LOOKBACK": "nope"}, 0},
		{"both", map[string]string{"BRIDGE_GITHUB_APP_ID": "7", "BRIDGE_GITHUB_APP_PRIVATE_KEY": key}, 6 * time.Hour},
	} {
		env := map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s"}
		maps.Copy(env, c.env)
		got, err := load(envOf(env))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if (got.App == nil) != (c.lookback == 0) || (got.App != nil && got.App.Lookback != c.lookback) {
			t.Errorf("%s: app %+v", c.name, got.App)
		}
	}
}

// TestConfigRefusals: each refused setting, its line's words and attributes, and the first problem wins in the
// order the settings were checked before the Config existed.
func TestConfigRefusals(t *testing.T) {
	key := keyPEM(t)
	app := map[string]string{"BRIDGE_GITHUB_APP_ID": "7", "BRIDGE_GITHUB_APP_PRIVATE_KEY": key}
	for _, c := range []struct {
		name string
		env  map[string]string
		msg  string
		args string
	}{
		{"no secret", map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": ""}, "BRIDGE_GITHUB_WEBHOOK_SECRET is required", "[]"},
		{"retention", map[string]string{"BRIDGE_RETENTION": "nope"}, "BRIDGE_RETENTION must be a Go duration of at least 24h", "[value nope]"},
		{"short retention", map[string]string{"BRIDGE_RETENTION": "23h59m"}, "BRIDGE_RETENTION must be a Go duration of at least 24h", "[value 23h59m]"},
		{"key", map[string]string{"BRIDGE_GITHUB_APP_ID": "7", "BRIDGE_GITHUB_APP_PRIVATE_KEY": "nope"}, "BRIDGE_GITHUB_APP_PRIVATE_KEY", "[err no PEM block in private key]"},
		{"lookback", map[string]string{"BRIDGE_RECONCILE_LOOKBACK": "nope"}, "BRIDGE_RECONCILE_LOOKBACK", `[err time: invalid duration "nope"]`},
		{"secret before retention", map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "", "BRIDGE_RETENTION": "nope"}, "BRIDGE_GITHUB_WEBHOOK_SECRET is required", "[]"},
		{"retention before key", map[string]string{"BRIDGE_RETENTION": "nope", "BRIDGE_GITHUB_APP_PRIVATE_KEY": "nope"}, "BRIDGE_RETENTION must be a Go duration of at least 24h", "[value nope]"},
	} {
		env := map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s"}
		maps.Copy(env, app)
		maps.Copy(env, c.env)
		_, err := load(envOf(env))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if err.msg != c.msg || fmtArgs(err.args) != c.args {
			t.Errorf("%s: %q %s, want %q %s", c.name, err.msg, fmtArgs(err.args), c.msg, c.args)
		}
	}
	if _, err := load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_RETENTION": "24h"})); err != nil {
		t.Errorf("exactly 24h: %v", err) // the positive control for the short retention
	}
}

func fmtArgs(args []any) string {
	s := make([]string, len(args))
	for i, a := range args {
		if e, ok := a.(error); ok {
			s[i] = e.Error()
		} else {
			s[i] = a.(string)
		}
	}
	return "[" + strings.Join(s, " ") + "]"
}

// TestConfigDocumented: envVars, load's own reads and README.md's Configuration table name the same variables.
func TestConfigDocumented(t *testing.T) {
	read := map[string]bool{}
	load(func(k string) string { read[k] = true; return "" })
	load(func(k string) string {
		read[k] = true
		return map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_GITHUB_APP_ID": "1", "BRIDGE_GITHUB_APP_PRIVATE_KEY": keyPEM(t)}[k]
	})
	listed := map[string]bool{}
	for _, v := range envVars {
		listed[v] = true
	}
	if !maps.Equal(read, listed) {
		t.Errorf("load reads %v, envVars lists %v", slices.Sorted(maps.Keys(read)), slices.Sorted(maps.Keys(listed)))
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, row := range regexp.MustCompile("(?m)^\\| (`[A-Z_]+`(?:, `[A-Z_]+`)*) \\|").FindAllStringSubmatch(string(readme), -1) {
		for _, v := range regexp.MustCompile("`([A-Z_]+)`").FindAllStringSubmatch(row[1], -1) {
			documented[v[1]] = true
		}
	}
	if !maps.Equal(documented, listed) {
		t.Errorf("README.md documents %v, envVars lists %v", slices.Sorted(maps.Keys(documented)), slices.Sorted(maps.Keys(listed)))
	}
	if len(listed) < 16 {
		t.Errorf("%d variables: the check no longer sees them", len(listed)) // the positive control
	}
}

// envReaders are what reads or changes the process's environment (as atlas's TestEnvBan, mountain env_test.go): os's
// and syscall's own, and the ones that read a variable on the caller's behalf. A package listed with no names is
// refused whole: os/exec reads PATH and hands the environment on, os/user reads HOME and USER. The check is
// syntactic: every use of a listed name is a selector on its import's name, or a dot import, which is refused; cgo
// and go:linkname are refused too.
var envReaders = map[string][]string{
	"os": {"Getenv", "LookupEnv", "Environ", "ExpandEnv", "Setenv", "Unsetenv", "Clearenv", "UserHomeDir", "UserCacheDir",
		"UserConfigDir", "TempDir", "MkdirTemp", "CreateTemp", "Getwd"},
	"syscall":  {"Getenv", "Environ", "Setenv", "Unsetenv", "Clearenv"},
	"net/http": {"ProxyFromEnvironment"},
	"os/exec":  nil,
	"os/user":  nil,
}

// envReadsAllowed is the one file that reads the environment (plan/15 §5: one Config per binary).
const envReadsAllowed = "cmd/bridge/config.go"

func envUses(name string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return nil, err
	}
	local := map[string]string{}
	var uses []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				uses = append(uses, "go:linkname")
			}
		}
	}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		names, ok := envReaders[p]
		if p == "C" || (ok && names == nil) {
			uses = append(uses, "import "+p)
			continue
		}
		if !ok {
			continue
		}
		n := path.Base(p)
		if im.Name != nil {
			n = im.Name.Name
		}
		if n == "." {
			uses = append(uses, "import . "+p)
			continue
		}
		local[n] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok && local[id.Name] != "" && slices.Contains(envReaders[local[id.Name]], s.Sel.Name) {
				uses = append(uses, local[id.Name]+"."+s.Sel.Name)
			}
		}
		return true
	})
	return uses, nil
}

// TestEnvBan: no non-test file of the module but cmd/bridge/config.go reads the environment (tests are exempt: the
// store's read BRIDGE_TEST_DATABASE_URL).
func TestEnvBan(t *testing.T) {
	root := "../.."
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		seen[path.Dir(rel)] = true
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		uses, err := envUses(rel, src)
		if err != nil {
			return err
		}
		switch {
		case rel == envReadsAllowed && len(uses) == 0:
			t.Errorf("%s reads no environment: the check no longer sees it", rel) // the positive control
		case rel != envReadsAllowed && len(uses) > 0:
			t.Errorf("%s reads the environment (%s): only %s does", rel, strings.Join(uses, ", "), envReadsAllowed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(root)
	for _, dir := range strings.Fields(string(out)) {
		if rel, _ := filepath.Rel(abs, dir); !seen[filepath.ToSlash(rel)] {
			t.Errorf("package %s was not walked", rel)
		}
	}
}

// TestEnvUses: each form the ban sees, and what it leaves alone.
func TestEnvUses(t *testing.T) {
	for _, c := range []struct {
		src  string
		want []string
	}{
		{`import "os"; var _ = os.Getenv("X")`, []string{"os.Getenv"}},
		{`import "os"; var f = os.LookupEnv`, []string{"os.LookupEnv"}},
		{`import o "os"; func g() { o.Environ() }`, []string{"os.Environ"}},
		{`import . "os"; var _ = Getenv("X")`, []string{"import . os"}},
		{`import "os"; var _, _ = os.UserHomeDir()`, []string{"os.UserHomeDir"}},
		{`import "syscall"; var _, _ = syscall.Getenv("X")`, []string{"syscall.Getenv"}},
		{`import h "net/http"; var _ = h.ProxyFromEnvironment`, []string{"net/http.ProxyFromEnvironment"}},
		{`import "os/exec"; var _ = exec.Command`, []string{"import os/exec"}},
		{`import u "os/user"; var _, _ = u.Current()`, []string{"import os/user"}},
		{`import "C"`, []string{"import C"}},
		{"import _ \"unsafe\"\n//go:linkname getenv syscall.Getenv\nfunc getenv(string) (string, bool)", []string{"go:linkname"}},
		{`import "os"; var _ = os.Args; var _ = os.Stderr`, nil},
		{`type t struct{ Getenv func(string) string }; var os t; var _ = os.Getenv`, nil}, // no import: not os
	} {
		got, err := envUses("x.go", []byte("package x\n"+c.src))
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.src, got, c.want)
		}
	}
}
