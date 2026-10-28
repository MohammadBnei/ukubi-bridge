package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestAlertLines: the chart's LogQL rules match the words of the bridge's lines (|= "..."); each line, rendered
// through the bridge's JSON logger, still holds them, and each is still logged by main.go.
func TestAlertLines(t *testing.T) {
	values, err := os.ReadFile("../../helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	filters := regexp.MustCompile(`\|= "([^"]+)"`).FindAllStringSubmatch(string(values), -1)
	if len(filters) < 2 {
		t.Fatalf("%d line filters in the chart: the check no longer sees them", len(filters)) // the positive control
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range filters {
		words := f[1]
		if !strings.Contains(string(src), `"`+words+`"`) {
			t.Errorf("%q: main.go logs no such line", words)
		}
		var buf bytes.Buffer
		newLogger(&buf).Warn(words, "subscription", "core", "err", errors.New("x"))
		if !strings.Contains(buf.String(), words) {
			t.Errorf("%q: not in its JSON line %s", words, buf.String())
		}
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
