// Finding the scan to compare a run with, and when each finding was first and last seen.

package store

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/model"
)

// Previous returns the newest finished scan before run id with the same
// targets and ports, the one "since last scan" compares against. It skips
// scans that stopped early or failed, since everything they missed would
// look fixed. ErrNotFound means there's no such scan yet.
func (s *Store) Previous(id int64) (Run, error) {
	cur, err := s.Run(id)
	if err != nil {
		return Run{}, err
	}
	rows, err := s.db.Query(`SELECT id, targets, settings FROM runs
		WHERE id < ? AND status = ? AND error = '' AND has_report = 1 ORDER BY id DESC`, id, Completed)
	if err != nil {
		return Run{}, fmt.Errorf("find previous scan: %w", err)
	}
	match := int64(0)
	for rows.Next() {
		var r Run
		var targets string
		if err := rows.Scan(&r.ID, &targets, &r.Settings); err != nil {
			_ = rows.Close()
			return Run{}, fmt.Errorf("find previous scan: %w", err)
		}
		if json.Unmarshal([]byte(targets), &r.Targets) == nil && SameScope(cur, r) {
			match = r.ID
			break
		}
	}
	if err := cmp.Or(rows.Err(), rows.Close()); err != nil {
		return Run{}, fmt.Errorf("find previous scan: %w", err)
	}
	if match == 0 {
		return Run{}, ErrNotFound
	}
	return s.Run(match)
}

// SameScope reports whether two runs scanned the same targets on the same
// ports. Only then can a finding missing from the newer one count as fixed.
func SameScope(a, b Run) bool {
	return slices.Equal(sorted(a.Targets), sorted(b.Targets)) && portsOf(a) == portsOf(b)
}

// portsOf reads the port settings, the only part of Settings the store looks
// inside. "nuqs scan" and the web UI both save them under these names.
func portsOf(r Run) string {
	var p struct {
		Ports    string `json:"ports"`
		TopPorts int    `json:"top_ports"`
	}
	_ = json.Unmarshal([]byte(r.Settings), &p) // no settings means the defaults
	return fmt.Sprintf("%s|%d", strings.ReplaceAll(p.Ports, " ", ""), p.TopPorts)
}

func sorted(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

// Seen is when a finding was found first and last, as scan start times.
type Seen struct {
	First, Last time.Time
}

// Seen returns when each of these findings was first and last found, across
// every saved scan.
func (s *Store) Seen(ids []string) (map[string]Seen, error) {
	seen := map[string]Seen{}
	if len(ids) == 0 {
		return seen, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.Query(`SELECT f.finding_id, min(r.started), max(r.started) FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE f.finding_id IN (?`+strings.Repeat(", ?", len(ids)-1)+`) GROUP BY f.finding_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("seen: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var first, last int64
		if err := rows.Scan(&id, &first, &last); err != nil {
			return nil, fmt.Errorf("seen: %w", err)
		}
		seen[id] = Seen{First: fromUnix(first), Last: fromUnix(last)}
	}
	return seen, rows.Err()
}

// SameScopeRuns returns every completed, error-free scan with the same targets
// and ports as run id, oldest first. If run id itself has a report (for example
// a stopped scan being viewed in the UI), it is included in chronological order.
func (s *Store) SameScopeRuns(id int64) ([]Run, error) {
	cur, err := s.Run(id)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, targets, settings FROM runs
		WHERE status = ? AND error = '' AND has_report = 1 ORDER BY started ASC, id ASC`, Completed)
	if err != nil {
		return nil, fmt.Errorf("list scope scans: %w", err)
	}
	var ids []int64
	hasCur := false
	for rows.Next() {
		var r Run
		var targets string
		if err := rows.Scan(&r.ID, &targets, &r.Settings); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("list scope scans: %w", err)
		}
		if json.Unmarshal([]byte(targets), &r.Targets) == nil && SameScope(cur, r) {
			ids = append(ids, r.ID)
			if r.ID == cur.ID {
				hasCur = true
			}
		}
	}
	if err := cmp.Or(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("list scope scans: %w", err)
	}
	out := make([]Run, 0, len(ids)+1)
	for _, rid := range ids {
		if rid == cur.ID {
			out = append(out, cur)
			continue
		}
		r, err := s.Run(rid)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if !hasCur && cur.Report != nil {
		out = append(out, cur)
		slices.SortFunc(out, func(a, b Run) int {
			return cmp.Or(a.Started.Compare(b.Started), cmp.Compare(a.ID, b.ID))
		})
	}
	return out, nil
}

// FindingMatch identifies one saved finding matching a finding ID or check ID
// query, together with the newest completed scan that observed it.
type FindingMatch struct {
	FindingID   string
	CheckID     string
	Host        string
	Port        int
	Protocol    string
	Title       string
	Severity    model.Severity
	LatestRunID int64
}

// FindFindingRuns lists distinct findings in completed, error-free scans whose
// finding_id or check_id equals query, newest seen first.
func (s *Store) FindFindingRuns(query string) ([]FindingMatch, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT f.finding_id, f.check_id, f.host, f.port, f.protocol, f.title, f.severity, r.id
		FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE r.status = ? AND r.error = '' AND r.has_report = 1 AND (f.finding_id = ? OR f.check_id = ?)
		ORDER BY r.started DESC, r.id DESC`, Completed, q, q)
	if err != nil {
		return nil, fmt.Errorf("find finding %q: %w", q, err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	var out []FindingMatch
	for rows.Next() {
		var m FindingMatch
		if err := rows.Scan(&m.FindingID, &m.CheckID, &m.Host, &m.Port, &m.Protocol, &m.Title, &m.Severity, &m.LatestRunID); err != nil {
			return nil, fmt.Errorf("find finding %q: %w", q, err)
		}
		if seen[m.FindingID] {
			continue
		}
		seen[m.FindingID] = true
		out = append(out, m)
	}
	return out, rows.Err()
}
