// Tests plain-text and JSON formatting for a finding's timeline across scans.

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/model"
)

func sampleTimeline() diff.Timeline {
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	return diff.Timeline{
		FindingID:   "telnet-open|192.168.1.1|23/tcp",
		CheckID:     "telnet-open",
		Title:       "Unencrypted Telnet server",
		Severity:    model.Medium,
		Host:        "192.168.1.1",
		Port:        23,
		Protocol:    "tcp",
		Targets:     []string{"192.168.1.1"},
		FirstSeen:   t0.Add(time.Hour),
		LastSeen:    t0.Add(5 * time.Hour),
		Reopened:    true,
		ReopenCount: 2,
		Entries: []diff.Entry{
			{ScanID: 1, Started: t0, State: diff.StateAbsent},
			{ScanID: 2, Started: t0.Add(time.Hour), State: diff.StateOpen, Evidence: "port 23/tcp is open\nsecond line"},
			{ScanID: 3, Started: t0.Add(2 * time.Hour), State: diff.StateFixed, Reason: diff.PortClosed},
			{ScanID: 4, Started: t0.Add(3 * time.Hour), State: diff.StateNotChecked, Reason: diff.HostDown},
			{ScanID: 5, Started: t0.Add(4 * time.Hour), State: diff.StateReopened, Evidence: "banner back"},
			{ScanID: 6, Started: t0.Add(5 * time.Hour), State: diff.StateReopened},
		},
	}
}

func TestTimelineText(t *testing.T) {
	var b bytes.Buffer
	if err := TimelineText(&b, sampleTimeline()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"[MEDIUM] Unencrypted Telnet server on 192.168.1.1:23/tcp (telnet-open)",
		"Finding: telnet-open|192.168.1.1|23/tcp",
		"Targets: 192.168.1.1",
		"First seen:",
		"Last seen:",
		"Reopened: came back after being fixed (2 times)",
		"Timeline (6 scans):",
		"SCAN", "STARTED", "STATUS", "DETAILS",
		"not found", "not present before first seen",
		"open", "port 23/tcp is open",
		"fixed", diff.PortClosed,
		"not checked", diff.HostDown,
		"reopened", "banner back (came back after being fixed)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "second line") {
		t.Errorf("multi-line evidence should truncate to first line:\n%s", out)
	}

	// Single scan and 1-time reopen wording.
	single := sampleTimeline()
	single.ReopenCount = 1
	single.Entries = single.Entries[:1]
	single.Entries[0].State = diff.State("custom")
	b.Reset()
	if err := TimelineText(&b, single); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(1 time)") || !strings.Contains(b.String(), "Timeline (1 scan):") || !strings.Contains(b.String(), "custom") {
		t.Errorf("unexpected singular output:\n%s", b.String())
	}
}

func TestTimelineJSON(t *testing.T) {
	var b bytes.Buffer
	tl := sampleTimeline()
	if err := TimelineJSON(&b, tl); err != nil {
		t.Fatal(err)
	}
	var got diff.Timeline
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.FindingID != tl.FindingID || !got.Reopened || got.ReopenCount != 2 || len(got.Entries) != len(tl.Entries) {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestTimelineWriteErrors(t *testing.T) {
	tl := sampleTimeline()
	if err := TimelineText(failWriter{}, tl); err == nil {
		t.Error("TimelineText should return write errors")
	}
	if err := TimelineJSON(failWriter{}, tl); err == nil {
		t.Error("TimelineJSON should return write errors")
	}
}
