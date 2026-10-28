package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestAlertLines: the chart's LogQL rules match the words of the bridge's lines (|= "..." or |~ "...", quoted or in
// backticks); each line, rendered through the bridge's JSON logger, still holds them, and some slog call in the
// module logs exactly them (the call's message, not a comment).
func TestAlertLines(t *testing.T) {
	values, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	filters := regexp.MustCompile("\\|[=~] (?:\"([^\"]+)\"|`([^`]+)`)").FindAllStringSubmatch(string(values), -1)
	if len(filters) != 2 {
		t.Fatalf("%d line filters in the chart, want the 2 this test was written for", len(filters)) // the positive control
	}
	messages := logMessages(t)
	for _, f := range filters {
		words := f[1] + f[2]
		if !messages[words] {
			t.Errorf("%q: no slog call logs these words", words)
		}
		var buf bytes.Buffer
		newLogger(&buf).Warn(words, "subscription", "core", "err", errors.New("x"))
		if !strings.Contains(buf.String(), words) {
			t.Errorf("%q: not in its JSON line %s", words, buf.String())
		}
	}
}

// logMessages is every constant message an slog call in the module's non-test files logs.
func logMessages(t *testing.T) map[string]bool {
	msgs := map[string]bool{}
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) == 0 {
				return true
			}
			if s, ok := c.Fun.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "slog" {
					if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						msgs[v] = true
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

// TestServerLog: the server sends net/http's own lines through the default logger at ERROR.
func TestServerLog(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)}") {
		t.Error("the server's ErrorLog is not the default logger at ERROR")
	}
}

// TestLogger: a line is one JSON object with its level and words.
func TestLogger(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf).Error("retention failed", "err", errors.New("conn refused"))
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil || m["level"] != "ERROR" || m["msg"] != "retention failed" || m["err"] != "conn refused" {
		t.Errorf("%s: %v", buf.Bytes(), err)
	}
	if _, ok := m["time"]; !ok {
		t.Errorf("no time: %s", buf.Bytes())
	}
}
