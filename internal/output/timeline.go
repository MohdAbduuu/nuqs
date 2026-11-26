// Prints the timeline of one finding across scans, as text for people or JSON for tools.

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/nuqs-org/nuqs/internal/diff"
)

// TimelineJSON writes one finding's timeline as indented JSON.
func TimelineJSON(w io.Writer, tl diff.Timeline) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(tl)
}

// TimelineText writes a plain-text timeline for one finding across scans.
func TimelineText(w io.Writer, tl diff.Timeline) error {
	p := &printer{w: w}
	p.f("[%s] %s on %s:%d/%s (%s)\n", strings.ToUpper(tl.Severity.String()), tl.Title, tl.Host, tl.Port, tl.Protocol, tl.CheckID)
	p.f("Finding: %s\n", tl.FindingID)
	if len(tl.Targets) > 0 {
		p.f("Targets: %s\n", strings.Join(tl.Targets, ", "))
	}
	if !tl.FirstSeen.IsZero() {
		p.f("First seen: %s  Last seen: %s\n", tl.FirstSeen.Local().Format("2006-01-02 15:04"), tl.LastSeen.Local().Format("2006-01-02 15:04"))
	}
	if tl.Reopened {
		times := "1 time"
		if tl.ReopenCount > 1 {
			times = fmt.Sprintf("%d times", tl.ReopenCount)
		}
		p.f("Reopened: came back after being fixed (%s)\n", times)
	}
	p.f("\nTimeline (%d %s):\n", len(tl.Entries), pluralWord(len(tl.Entries), "scan", "scans"))
	if p.err != nil {
		return p.err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SCAN\tSTARTED\tSTATUS\tDETAILS")
	for _, e := range tl.Entries {
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", e.ScanID, e.Started.Local().Format("2006-01-02 15:04"), e.State.Label(), timelineEntryDetail(e))
	}
	return tw.Flush()
}

func timelineEntryDetail(e diff.Entry) string {
	switch e.State {
	case diff.StateReopened:
		ev := firstLine(e.Evidence)
		if ev != "" {
			return ev + " (came back after being fixed)"
		}
		return "came back after being fixed"
	case diff.StateOpen:
		return firstLine(e.Evidence)
	case diff.StateAbsent:
		return "not present before first seen"
	default:
		return e.Reason
	}
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
