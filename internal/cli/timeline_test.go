// Tests "nuqs show --finding" timelines in text and JSON, reopened detection and lookup errors.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/model"
)

func withoutTelnetPort(t *testing.T) []byte {
	t.Helper()
	xml, err := os.ReadFile("testdata/router.xml")
	if err != nil {
		t.Fatal(err)
	}
	fixed := regexp.MustCompile(`<port protocol="tcp" portid="23">.*</port>\r?\n`).ReplaceAll(xml, nil)
	if bytes.Equal(fixed, xml) {
		t.Fatal("testdata/router.xml has no telnet port to remove")
	}
	return fixed
}

func TestShowFindingTimeline(t *testing.T) {
	origXML, err := os.ReadFile("testdata/router.xml")
	if err != nil {
		t.Fatal(err)
	}
	fixedXML := withoutTelnetPort(t)
	r := &fakeRunner{out: origXML}
	app, out, errOut := newApp(t, r)
	ctx := context.Background()

	scan := func(xml []byte, args ...string) {
		t.Helper()
		r.out = xml
		errOut.Reset()
		if code := app.Run(ctx, append([]string{"scan"}, args...)); code != ExitOK {
			t.Fatalf("scan %v exit %d:\n%s", args, code, errOut)
		}
	}

	scan(origXML, "192.168.1.0/30", "-p", "23")  // scan 1: open
	scan(origXML, "192.168.1.0/30", "-p", "22")  // scan 2: different ports, excluded
	scan(fixedXML, "192.168.1.0/30", "-p", "23") // scan 3: fixed
	scan(origXML, "192.168.1.0/30", "-p", "23")  // scan 4: reopened

	// Text output by check ID.
	out.Reset()
	errOut.Reset()
	if code := app.Run(ctx, []string{"show", "--finding", "telnet-open"}); code != ExitOK {
		t.Fatalf("show --finding exit %d:\n%s", code, errOut)
	}
	for _, want := range []string{
		"[MEDIUM]", "telnet-open|192.168.1.1|23/tcp",
		"First seen:", "Last seen:",
		"Reopened: came back after being fixed (1 time)",
		"Timeline (3 scans):",
		"open", "fixed", diff.PortClosed, "reopened",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("timeline missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "\n  2 ") {
		t.Errorf("scan 2 with different ports should be excluded:\n%s", out)
	}

	// JSON output with scan ID before --finding, anchored on the scan where it was fixed.
	out.Reset()
	errOut.Reset()
	if code := app.Run(ctx, []string{"show", "3", "--finding", "telnet-open", "--json"}); code != ExitOK {
		t.Fatalf("show 3 --finding --json exit %d:\n%s", code, errOut)
	}
	var tl diff.Timeline
	if err := json.Unmarshal(out.Bytes(), &tl); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if !tl.Reopened || tl.ReopenCount != 1 || len(tl.Entries) != 3 {
		t.Fatalf("unexpected JSON timeline: %+v", tl)
	}
	if tl.Entries[0].ScanID != 1 || tl.Entries[0].State != diff.StateOpen ||
		tl.Entries[1].ScanID != 3 || tl.Entries[1].State != diff.StateFixed ||
		tl.Entries[2].ScanID != 4 || tl.Entries[2].State != diff.StateReopened {
		t.Errorf("unexpected entries: %+v", tl.Entries)
	}

	// Exact finding ID also works with scan ID after --finding.
	fid := model.FindingID("192.168.1.1", "telnet-open", 23, "tcp")
	out.Reset()
	if code := app.Run(ctx, []string{"show", "--finding", fid, "4"}); code != ExitOK {
		t.Fatalf("exact finding ID exit %d:\n%s", code, errOut)
	}
	if !strings.Contains(out.String(), "Finding: "+fid) {
		t.Errorf("missing finding ID in output:\n%s", out)
	}
}

func TestShowFindingAmbiguousAndErrors(t *testing.T) {
	const twoHostXML = `<nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed"/></port>
</ports></host>
<host><status state="up"/><address addr="192.168.1.2" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed"/></port>
</ports></host>
</nmaprun>`

	r := &fakeRunner{out: []byte(twoHostXML)}
	app, out, errOut := newApp(t, r)
	ctx := context.Background()

	if code := app.Run(ctx, []string{"scan", "192.168.1.0/30", "-p", "23"}); code != ExitOK {
		t.Fatalf("scan exit %d:\n%s", code, errOut)
	}

	// Ambiguous check_id lists full finding IDs for both hosts.
	errOut.Reset()
	if code := app.Run(ctx, []string{"show", "--finding", "telnet-open"}); code != ExitError {
		t.Fatalf("ambiguous check_id: exit %d, want %d", code, ExitError)
	}
	for _, want := range []string{
		"more than one finding matches",
		"nuqs show --finding 'telnet-open|192.168.1.1|23/tcp'",
		"nuqs show --finding 'telnet-open|192.168.1.2|23/tcp'",
	} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("ambiguous error missing %q:\n%s", want, errOut)
		}
	}

	// Passing the full finding ID resolves cleanly.
	out.Reset()
	errOut.Reset()
	if code := app.Run(ctx, []string{"show", "--finding", "telnet-open|192.168.1.2|23/tcp"}); code != ExitOK {
		t.Fatalf("disambiguated finding exit %d:\n%s", code, errOut)
	}
	if !strings.Contains(out.String(), "192.168.1.2:23/tcp") {
		t.Errorf("expected host 192.168.1.2:\n%s", out)
	}

	// Error and usage cases.
	for _, args := range [][]string{
		{"show", "--finding", "telnet-open", "abc"},
		{"show", "--finding", "telnet-open", "1", "2"},
		{"show", "--finding"},
		{"show", "--finding", "", "1"},
		{"show", "--finding", "   ", "1"},
	} {
		if code := app.Run(ctx, args); code != ExitUsage {
			t.Errorf("%v: exit %d, want ExitUsage", args, code)
		}
	}
	for _, args := range [][]string{
		{"show", "--finding", "nope"},
		{"show", "--finding", "nope", "1"},
		{"show", "--finding", "telnet-open", "99"},
		{"show", "--finding", "telnet-open", "0"},
	} {
		if code := app.Run(ctx, args); code != ExitError {
			t.Errorf("%v: exit %d, want ExitError", args, code)
		}
	}
}
