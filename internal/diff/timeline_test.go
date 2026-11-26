// Tests building a finding's timeline across scans, including fixed, not checked and reopened transitions.

package diff

import (
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

func TestBuildTimelineLifecycle(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	fid := model.FindingID("192.168.1.1", "telnet-open", 23, "tcp")
	finding := func(evidence string, conf model.Confidence) model.Finding {
		return model.Finding{
			ID:         fid,
			CheckID:    "telnet-open",
			Title:      "Unencrypted Telnet server",
			Severity:   model.Medium,
			Confidence: conf,
			Host:       "192.168.1.1",
			Port:       23,
			Protocol:   "tcp",
			Evidence:   evidence,
		}
	}
	hostWithTelnet := []model.Host{{
		Address:  "192.168.1.1",
		Services: []model.Service{{Port: 23, Protocol: "tcp", Name: "telnet"}},
	}}
	hostWithoutTelnet := []model.Host{{
		Address:  "192.168.1.1",
		Services: []model.Service{{Port: 22, Protocol: "tcp", Name: "ssh"}},
	}}

	scans := []ScanReport{
		{
			ID: 1, Name: "clean before", Started: t0, Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithoutTelnet},
		},
		{
			ID: 2, Name: "first open", Started: t0.Add(time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithTelnet, Findings: []model.Finding{finding("port 23 open", "")}},
		},
		{
			ID: 3, Name: "port closed", Started: t0.Add(2 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithoutTelnet},
		},
		{
			ID: 4, Name: "host down", Started: t0.Add(3 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{},
		},
		{
			ID: 5, Name: "came back", Started: t0.Add(4 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithTelnet, Findings: []model.Finding{finding("banner back", model.Confirmed)}},
		},
		{
			ID: 6, Name: "check passed", Started: t0.Add(5 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithTelnet},
		},
		{
			ID: 7, Name: "check errored", Started: t0.Add(6 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{
				Hosts:  hostWithTelnet,
				Errors: []engine.CheckError{{CheckID: "telnet-open", Host: "192.168.1.1", Port: 23, Error: "timed out"}},
			},
		},
		{
			ID: 8, Name: "came back again", Started: t0.Add(7 * time.Hour), Targets: []string{"192.168.1.1"},
			Report: &engine.Report{Hosts: hostWithTelnet, Findings: []model.Finding{finding("banner again", model.Inferred)}},
		},
	}

	tl, ok := BuildTimeline(fid, scans)
	if !ok {
		t.Fatal("expected timeline to be built")
	}
	if tl.FindingID != fid || tl.CheckID != "telnet-open" || tl.Host != "192.168.1.1" || tl.Port != 23 || tl.Protocol != "tcp" {
		t.Errorf("unexpected metadata: %+v", tl)
	}
	if !tl.FirstSeen.Equal(t0.Add(time.Hour)) || !tl.LastSeen.Equal(t0.Add(7*time.Hour)) {
		t.Errorf("seen window: first=%v last=%v", tl.FirstSeen, tl.LastSeen)
	}
	if !tl.Reopened || tl.ReopenCount != 2 {
		t.Errorf("want Reopened=true ReopenCount=2, got %v %d", tl.Reopened, tl.ReopenCount)
	}
	want := []struct {
		id     int64
		state  State
		reason string
	}{
		{1, StateAbsent, ""},
		{2, StateOpen, ""},
		{3, StateFixed, PortClosed},
		{4, StateNotChecked, HostDown},
		{5, StateReopened, ""},
		{6, StateFixed, CheckPassed},
		{7, StateNotChecked, CheckFailed},
		{8, StateReopened, ""},
	}
	if len(tl.Entries) != len(want) {
		t.Fatalf("entries: got %d, want %d", len(tl.Entries), len(want))
	}
	for i, w := range want {
		e := tl.Entries[i]
		if e.ScanID != w.id || e.State != w.state || e.Reason != w.reason {
			t.Errorf("entry %d: got (%d, %q, %q), want (%d, %q, %q)", i, e.ScanID, e.State, e.Reason, w.id, w.state, w.reason)
		}
	}
	if tl.Entries[1].Confidence != model.Confirmed {
		t.Errorf("empty confidence should default to confirmed, got %q", tl.Entries[1].Confidence)
	}
	if got := tl.Summary(); got != "seen in 3 of 8 scans, came back after being fixed" {
		t.Errorf("summary: %q", got)
	}
	// If fixed again after being reopened, the summary mentions both.
	reopenedThenFixed := tl
	reopenedThenFixed.Entries = append(reopenedThenFixed.Entries, Entry{ScanID: 9, State: StateFixed, Reason: PortClosed})
	if got := reopenedThenFixed.Summary(); got != "seen in 3 of 9 scans, came back after being fixed, now fixed" {
		t.Errorf("reopened then fixed summary: %q", got)
	}
}

func TestBuildTimelineNotCheckedDoesNotTriggerReopen(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	fid := model.FindingID("10.0.0.1", "ssh-password-auth", 22, "tcp")
	f := model.Finding{ID: fid, CheckID: "ssh-password-auth", Title: "SSH password auth", Severity: model.Medium, Host: "10.0.0.1", Port: 22, Protocol: "tcp"}
	host := []model.Host{{Address: "10.0.0.1", Services: []model.Service{{Port: 22, Protocol: "tcp", Name: "ssh"}}}}

	scans := []ScanReport{
		{ID: 1, Started: t0, Report: &engine.Report{Hosts: host, Findings: []model.Finding{f}}},
		{ID: 2, Started: t0.Add(time.Hour), Report: &engine.Report{}},
		{ID: 3, Started: t0.Add(2 * time.Hour), Report: &engine.Report{Hosts: host, Errors: []engine.CheckError{{CheckID: "ssh-password-auth", Host: "10.0.0.1", Port: 22, Error: "reset"}}}},
		{ID: 4, Started: t0.Add(3 * time.Hour), Report: &engine.Report{Hosts: host, Findings: []model.Finding{f}}},
	}
	tl, ok := BuildTimeline(fid, scans)
	if !ok {
		t.Fatal("expected timeline")
	}
	if tl.Reopened || tl.ReopenCount != 0 {
		t.Errorf("not_checked between open scans must not flag reopened: %+v", tl)
	}
	if tl.Entries[3].State != StateOpen {
		t.Errorf("entry 3 state = %q, want open", tl.Entries[3].State)
	}
	if got := tl.Summary(); got != "seen in 2 of 4 scans" {
		t.Errorf("summary: %q", got)
	}
}

func TestBuildTimelineSortingAndEdgeCases(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	fid := model.FindingID("10.0.0.5", "telnet-open", 23, "tcp")
	f := model.Finding{ID: fid, CheckID: "telnet-open", Title: "Telnet", Severity: model.Medium, Host: "10.0.0.5", Port: 23, Protocol: "tcp"}
	hostUp := []model.Host{{Address: "10.0.0.5"}}

	// Missing finding returns false.
	if _, ok := BuildTimeline("missing", []ScanReport{{ID: 1, Report: &engine.Report{}}}); ok {
		t.Error("missing finding should return false")
	}

	// Out-of-order inputs, nil report skipped, Targets fallback to Report.Targets.
	scans := []ScanReport{
		{ID: 2, Started: t0.Add(time.Hour), Report: &engine.Report{Targets: []string{"10.0.0.5"}, Hosts: hostUp}},
		{ID: 99, Started: t0.Add(2 * time.Hour), Report: nil},
		{ID: 1, Started: t0, Report: &engine.Report{Targets: []string{"10.0.0.5"}, Hosts: hostUp, Findings: []model.Finding{f}}},
	}
	tl, ok := BuildTimeline(fid, scans)
	if !ok {
		t.Fatal("expected timeline")
	}
	if len(tl.Entries) != 2 || tl.Entries[0].ScanID != 1 || tl.Entries[1].ScanID != 2 {
		t.Fatalf("scans should be ordered chronologically with nil skipped: %+v", tl.Entries)
	}
	if len(tl.Targets) != 1 || tl.Targets[0] != "10.0.0.5" {
		t.Errorf("targets fallback: %v", tl.Targets)
	}
	if got := tl.Summary(); got != "seen in 1 of 2 scans, fixed" {
		t.Errorf("fixed summary: %q", got)
	}

	single, ok := BuildTimeline(fid, []ScanReport{scans[2]})
	if !ok || single.Summary() != "seen in 1 of 1 scan" {
		t.Errorf("single scan summary: %v %q", ok, single.Summary())
	}
}

func TestStateLabel(t *testing.T) {
	for state, want := range map[State]string{
		StateOpen:       "open",
		StateReopened:   "reopened",
		StateFixed:      "fixed",
		StateNotChecked: "not checked",
		StateAbsent:     "not found",
		State("custom"): "custom",
	} {
		if got := state.Label(); got != want {
			t.Errorf("State(%q).Label() = %q, want %q", state, got, want)
		}
	}
}
