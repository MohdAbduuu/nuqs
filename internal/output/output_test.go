// Tests every scan report format.

package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

func sample() *engine.Report {
	start := time.Date(2026, 11, 16, 22, 0, 0, 0, time.UTC)
	return &engine.Report{
		Targets:  []string{"192.168.1.1"},
		Started:  start,
		Finished: start.Add(2500 * time.Millisecond),
		Hosts:    []model.Host{{Address: "192.168.1.1", Services: []model.Service{{Port: 23, Protocol: "tcp", Name: "telnet"}, {Port: 80, Protocol: "tcp", Name: "http"}}}},
		Findings: []model.Finding{{
			ID: "telnet-open|192.168.1.1|23/tcp", CheckID: "telnet-open", Title: "Unencrypted Telnet server", Severity: model.Medium, Confidence: model.Confirmed,
			Host: "192.168.1.1", Port: 23, Protocol: "tcp", Evidence: "port 23/tcp is open", Fix: "Turn off Telnet.",
		}},
		Errors: []engine.CheckError{{CheckID: "http-security-headers", Host: "192.168.1.1", Port: 80, Error: "connection reset\nmore detail"}},
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Scanned 192.168.1.1 in 2.5s",
		"Hosts up: 1, open services: 2",
		"Findings (1):",
		"CONFIDENCE", "MEDIUM", "confirmed", "192.168.1.1",
		"Unencrypted Telnet server on 192.168.1.1:23 (confirmed)", "23/tcp", "telnet-open", "Unencrypted Telnet server",
		"Evidence: port 23/tcp is open",
		"Fix: Turn off Telnet.",
		"Checks that could not finish (1):",
		"http-security-headers on 192.168.1.1:80: connection reset",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "more detail") {
		t.Error("only the first line of an error should be shown")
	}
}

func TestTextMultilineEvidence(t *testing.T) {
	r := sample()
	r.Findings[0].Evidence = "line one\nline two"
	var b bytes.Buffer
	if err := Text(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "    Evidence: line one\n              line two\n") {
		t.Errorf("multiline evidence not indented:\n%s", b.String())
	}
}

func TestTextNoFindings(t *testing.T) {
	r := sample()
	r.Findings, r.Errors = nil, nil
	var b bytes.Buffer
	if err := Text(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No findings.") || strings.Contains(b.String(), "could not finish") {
		t.Errorf("unexpected output:\n%s", b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var back engine.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(back.Findings) != 1 || back.Findings[0].Severity != model.Medium || back.Hosts[0].Services[1].Port != 80 {
		t.Errorf("JSON lost data: %+v", back)
	}
	if !strings.Contains(b.String(), `"confidence": "confirmed"`) {
		t.Error("confidence should be in the JSON")
	}
	if !strings.Contains(b.String(), `"severity": "medium"`) {
		t.Error("severity should be written as a name")
	}
}

func TestHTML(t *testing.T) {
	r := sample()
	r.Findings[0].Evidence = `<script>alert("evidence")</script>`
	r.Findings[0].Fix = `disable <telnet> & verify`
	var b bytes.Buffer
	if err := HTML(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<!doctype html>", "Nuqs scan report", "192.168.1.1:23/tcp", "Unencrypted Telnet server", "disable &lt;telnet&gt; &amp; verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML is missing %q", want)
		}
	}
	if strings.Contains(out, `<script>alert`) {
		t.Error("HTML must escape report content")
	}
}

func TestCSV(t *testing.T) {
	r := sample()
	r.Findings[0].Title = `=HYPERLINK("https://example.test")`
	r.Findings[0].Evidence = "line one\nline two"
	var b bytes.Buffer
	if err := CSV(&b, r); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("CSV cannot be read: %v\n%s", err, b.String())
	}
	if len(rows) != 2 || len(rows[0]) != 10 {
		t.Fatalf("CSV dimensions: %#v", rows)
	}
	if rows[1][7] != `'=`+`HYPERLINK("https://example.test")` {
		t.Errorf("formula-like title was not made safe: %q", rows[1][7])
	}
	if rows[1][8] != "line one\nline two" {
		t.Errorf("multiline evidence was not preserved: %q", rows[1][8])
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteErrors(t *testing.T) {
	if err := Text(failWriter{}, sample()); err == nil {
		t.Error("Text should return write errors")
	}
	r := sample()
	r.Findings = nil
	if err := Text(failWriter{}, r); err == nil {
		t.Error("Text should return write errors even without findings")
	}
	if err := JSON(failWriter{}, sample()); err == nil {
		t.Error("JSON should return write errors")
	}
	for name, write := range map[string]func(io.Writer, *engine.Report) error{"HTML": HTML, "CSV": CSV} {
		if err := write(failWriter{}, sample()); err == nil {
			t.Errorf("%s should return write errors", name)
		}
	}
}

func TestTextEmptyConfidence(t *testing.T) {
	r := sample()
	r.Findings[0].Confidence = ""
	var b bytes.Buffer
	if err := Text(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "()") || !strings.Contains(b.String(), "(confirmed)") {
		t.Errorf("an empty confidence should print as confirmed:\n%s", b.String())
	}
}
