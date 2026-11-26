// Timeline of one finding across scans of the same targets and ports, flagging
// findings that came back after being fixed.

package diff

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

// State describes what one scan saw for a finding.
type State string

// Timeline states for one finding in a scan.
const (
	StateOpen       State = "open"        // finding was present
	StateReopened   State = "reopened"    // finding came back after being fixed in an earlier scan
	StateFixed      State = "fixed"       // scan checked the scope and did not find it
	StateNotChecked State = "not_checked" // host didn't answer or the check couldn't finish
	StateAbsent     State = "not_found"   // clean scan before the finding was first seen
)

// Label returns the plain-words status shown in the CLI and web UI.
func (s State) Label() string {
	switch s {
	case StateOpen:
		return "open"
	case StateReopened:
		return "reopened"
	case StateFixed:
		return "fixed"
	case StateNotChecked:
		return "not checked"
	case StateAbsent:
		return "not found"
	default:
		return string(s)
	}
}

// ScanReport pairs a scan's metadata with its report for building a timeline.
type ScanReport struct {
	ID      int64
	Name    string
	Started time.Time
	Targets []string
	Report  *engine.Report
}

// Entry is one scan's row in a finding's timeline.
type Entry struct {
	ScanID     int64            `json:"scan_id,omitzero"`
	ScanName   string           `json:"scan_name,omitempty"`
	Started    time.Time        `json:"started"`
	State      State            `json:"state"`
	Reason     string           `json:"reason,omitempty"`     // why it's fixed or not_checked
	Evidence   string           `json:"evidence,omitempty"`   // what we saw when open or reopened
	Confidence model.Confidence `json:"confidence,omitempty"` // confirmed or inferred when open or reopened
}

// Timeline tracks one finding across every scan of the same targets and ports.
type Timeline struct {
	FindingID   string         `json:"finding_id"`
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Severity    model.Severity `json:"severity"`
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Protocol    string         `json:"protocol"`
	Targets     []string       `json:"targets,omitempty"`
	FirstSeen   time.Time      `json:"first_seen,omitzero"`
	LastSeen    time.Time      `json:"last_seen,omitzero"`
	Reopened    bool           `json:"reopened"`               // true if it ever came back after being fixed
	ReopenCount int            `json:"reopen_count,omitempty"` // how many times it came back after being fixed
	Entries     []Entry        `json:"entries"`                // chronological, oldest first
}

// BuildTimeline builds the chronological timeline for findingID across scans
// of the same targets and ports. It returns false when findingID never appeared
// in any of the provided scans.
func BuildTimeline(findingID string, scans []ScanReport) (Timeline, bool) {
	ordered := make([]ScanReport, 0, len(scans))
	for _, sc := range scans {
		if sc.Report != nil {
			ordered = append(ordered, sc)
		}
	}
	slices.SortFunc(ordered, func(a, b ScanReport) int {
		return cmp.Or(a.Started.Compare(b.Started), cmp.Compare(a.ID, b.ID))
	})

	// Locate the finding's metadata from its latest appearance in these scans.
	var meta model.Finding
	found := false
	for _, sc := range ordered {
		for _, f := range sc.Report.Findings {
			if f.ID == findingID {
				meta = f
				found = true
			}
		}
	}
	if !found {
		return Timeline{}, false
	}

	tl := Timeline{
		FindingID: meta.ID,
		CheckID:   meta.CheckID,
		Title:     meta.Title,
		Severity:  meta.Severity,
		Host:      meta.Host,
		Port:      meta.Port,
		Protocol:  meta.Protocol,
		Entries:   make([]Entry, 0, len(ordered)),
	}
	if len(ordered) > 0 {
		tl.Targets = slices.Clone(ordered[len(ordered)-1].Targets)
		if len(tl.Targets) == 0 {
			tl.Targets = slices.Clone(ordered[len(ordered)-1].Report.Targets)
		}
	}

	seenBefore := false
	var lastDecisive State // StateOpen or StateFixed; StateNotChecked does not erase it
	for _, sc := range ordered {
		e := Entry{
			ScanID:   sc.ID,
			ScanName: sc.Name,
			Started:  sc.Started,
		}
		if match, ok := findInReport(sc.Report, findingID); ok {
			if tl.FirstSeen.IsZero() {
				tl.FirstSeen = sc.Started
			}
			tl.LastSeen = sc.Started
			e.Evidence = match.Evidence
			e.Confidence = match.Confidence
			if e.Confidence == "" {
				e.Confidence = model.Confirmed
			}
			if seenBefore && lastDecisive == StateFixed {
				e.State = StateReopened
				tl.Reopened = true
				tl.ReopenCount++
			} else {
				e.State = StateOpen
			}
			seenBefore = true
			lastDecisive = StateOpen
			tl.Entries = append(tl.Entries, e)
			continue
		}

		e.State, e.Reason = classifyMissing(sc.Report, meta, seenBefore)
		if e.State == StateFixed {
			lastDecisive = StateFixed
		}
		tl.Entries = append(tl.Entries, e)
	}
	return tl, true
}

// Summary returns a short plain-words status line for the timeline.
func (t Timeline) Summary() string {
	present := 0
	for _, e := range t.Entries {
		if e.State == StateOpen || e.State == StateReopened {
			present++
		}
	}
	base := fmt.Sprintf("seen in %d of %d %s", present, len(t.Entries), pluralScans(len(t.Entries)))
	latestFixed := len(t.Entries) > 0 && t.Entries[len(t.Entries)-1].State == StateFixed
	switch {
	case t.Reopened && latestFixed:
		return base + ", came back after being fixed, now fixed"
	case t.Reopened:
		return base + ", came back after being fixed"
	case latestFixed:
		return base + ", fixed"
	default:
		return base
	}
}

func findInReport(rep *engine.Report, findingID string) (model.Finding, bool) {
	for _, f := range rep.Findings {
		if f.ID == findingID {
			return f, true
		}
	}
	return model.Finding{}, false
}

func classifyMissing(rep *engine.Report, meta model.Finding, seenBefore bool) (State, string) {
	hostUp := false
	portOpen := false
	for _, h := range rep.Hosts {
		if h.Address != meta.Host {
			continue
		}
		hostUp = true
		for _, sv := range h.Services {
			if sv.Port == meta.Port && sv.Protocol == meta.Protocol {
				portOpen = true
				break
			}
		}
		break
	}
	if !hostUp {
		return StateNotChecked, HostDown
	}
	for _, err := range rep.Errors {
		if err.CheckID == meta.CheckID && err.Host == meta.Host && err.Port == meta.Port {
			return StateNotChecked, CheckFailed
		}
	}
	if !seenBefore {
		return StateAbsent, ""
	}
	if !portOpen {
		return StateFixed, PortClosed
	}
	return StateFixed, CheckPassed
}

func pluralScans(n int) string {
	if n == 1 {
		return "scan"
	}
	return "scans"
}
