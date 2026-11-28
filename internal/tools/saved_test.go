// Tests for saving web UI scans to the store and loading them after a restart.

package tools

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/diff"
	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/store"
)

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestScansAreSavedAndComeBackAfterARestart(t *testing.T) {
	dir := t.TempDir()
	st := openStore(t, dir)
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	s, err := m.Start(NewScan{Name: "Lab", Description: "telnet box", Kind: "full", StartedBy: "alice", Settings: ScanRequest{Target: "127.0.0.1", Ports: "23"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "1" {
		t.Errorf("the store gives the ID, got %q", s.ID)
	}
	done := waitFor(t, m, s.ID, finished)

	// The store has it as soon as the scan shows as finished.
	saved, err := st.Run(1)
	if err != nil || saved.Status != store.Completed || saved.Report == nil || len(saved.Report.Findings) != 1 {
		t.Fatalf("saved: %+v, %v", saved, err)
	}

	// A new server on the same store shows the same scan.
	again := &Scans{Service: m.Service, Store: openStore(t, dir)}
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if len(list) != 1 {
		t.Fatalf("after restart: %+v", list)
	}
	got := list[0]
	if got.ID != "1" || got.Name != "Lab" || got.Description != "telnet box" || got.Kind != "full" || got.StartedBy != "alice" ||
		got.Settings.Ports != "23" || got.Status != ScanCompleted || got.Percent != 100 || got.HostsFound != 1 ||
		len(got.Report.Findings) != 1 || !got.Finished.Equal(done.Finished) {
		t.Errorf("after restart: %+v", got)
	}

	// IDs keep counting up from the saved ones.
	next, err := again.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, again, next.ID, finished)
	if next.ID != "2" {
		t.Errorf("next ID %q", next.ID)
	}
	again.StopAll() // loaded scans can be "stopped" safely, they're done
}

func TestOlderScansLoadFromTheStore(t *testing.T) {
	st := openStore(t, t.TempDir())
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, Keep: 1}
	first, _ := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	waitFor(t, m, first.ID, finished)
	second, _ := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	waitFor(t, m, second.ID, finished)

	if len(m.List()) != 1 {
		t.Fatalf("memory keeps %d", len(m.List()))
	}
	old, ok := m.Get(first.ID)
	if !ok || old.Status != ScanCompleted || old.Report == nil {
		t.Errorf("the first scan should load from the store: %+v", old)
	}
	if err := m.Stop(first.ID); err != nil {
		t.Errorf("stopping a finished saved scan: %v", err)
	}
	for _, id := range []string{"99", "abc"} {
		if _, ok := m.Get(id); ok {
			t.Errorf("scan %s shouldn't exist", id)
		}
		if err := m.Stop(id); err != ErrNotFound {
			t.Errorf("stop %s: %v", id, err)
		}
	}
}

func TestListPicksUpScansTheCLISaved(t *testing.T) {
	st := openStore(t, t.TempDir())
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, Keep: 2}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	web, _ := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	waitFor(t, m, web.ID, finished)

	// "nuqs scan" saves two scans while the server runs.
	for range 2 {
		r := store.Run{Name: "from cli", Kind: "cli", Targets: []string{"10.0.0.1"}, Status: store.Completed, Started: time.Now()}
		if err := st.Save(&r); err != nil {
			t.Fatal(err)
		}
	}
	list := m.List()
	if len(list) != 2 || list[0].ID != "3" || list[1].ID != "2" || list[0].KindName() != "Command line scan" {
		t.Fatalf("want the 2 newest, got %+v", list)
	}
	if again := m.List(); len(again) != 2 || again[0].ID != "3" {
		t.Errorf("listing twice should give the same: %+v", again)
	}
	if old, ok := m.Get(web.ID); !ok || old.Report == nil {
		t.Errorf("the web scan that dropped off the list still loads: %+v", old)
	}

	// A scan another server is still running isn't listed until it's done.
	other := store.Run{Name: "elsewhere", Kind: "quick", Targets: []string{"10.0.0.1"}, Started: time.Now()}
	if err := st.Create(&other); err != nil {
		t.Fatal(err)
	}
	m.Keep = 10
	for _, s := range m.List() {
		if s.ID == "4" {
			t.Error("a scan running elsewhere shouldn't be listed")
		}
	}

	// Our own running scan stays at the top.
	release := make(chan struct{})
	m.Service = newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)})
	running, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if list := m.List(); list[0].ID != running.ID || list[0].Status != ScanRunning {
		t.Errorf("running scan not first: %+v", list[0])
	}
	close(release)
	waitFor(t, m, running.ID, finished)

	st.Close()
	if len(m.List()) == 0 {
		t.Error("the scans in memory should still show when the store can't be read")
	}
}

func TestLoadClosesScansACrashLeftRunning(t *testing.T) {
	st := openStore(t, t.TempDir())
	r := store.Run{Name: "cut off", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: time.Now()}
	if err := st.Create(&r); err != nil {
		t.Fatal(err)
	}
	m := &Scans{Service: newTestService(&fakeRunner{}), Store: st}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	s, ok := m.Get("1")
	if !ok || s.Status != ScanStopped || s.Error == "" || s.Settings.Target != "" {
		t.Errorf("%+v", s)
	}
	// A new scan can start, the old one doesn't count as running.
	if _, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}}); err != nil {
		t.Error(err)
	}
}

func TestStoreProblemsAreReported(t *testing.T) {
	st := openStore(t, t.TempDir())
	m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st}
	st.Close()
	if err := m.Load(); err == nil {
		t.Error("load from a closed store should fail")
	}
	if _, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}}); err == nil {
		t.Error("start should fail when the scan can't be saved")
	}
}

func TestFinishedButNotSaved(t *testing.T) {
	st := openStore(t, t.TempDir())
	release := make(chan struct{})
	m := &Scans{Service: newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)}), Store: st}
	s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // the disk went away mid-scan
	close(release)
	done := waitFor(t, m, s.ID, finished)
	if done.Status != ScanCompleted || done.Report == nil || !strings.Contains(done.Error, "couldn't be saved") {
		t.Errorf("%+v", done)
	}
}

func TestCommandLineScanKind(t *testing.T) {
	if got := (Scan{Kind: "cli"}).KindName(); got != "Command line scan" {
		t.Errorf("got %q", got)
	}
}

// Regression: refreshing the list from the store while a scan starts must
// not drop the running scan from memory, or its progress and Stop break.
func TestRefreshKeepsAScanThatStartsMeanwhile(t *testing.T) {
	st := openStore(t, t.TempDir())
	for range 50 {
		r := store.Run{Name: "saved", Kind: "cli", Targets: []string{"127.0.0.1"}, Status: store.Completed, Started: time.Now()}
		r.Report = &engine.Report{Targets: r.Targets, Findings: []model.Finding{}, Errors: []engine.CheckError{}}
		for i := range 40 {
			r.Report.Findings = append(r.Report.Findings, model.Finding{ID: strconv.Itoa(i), CheckID: "telnet-open", Host: "127.0.0.1", Confidence: model.Confirmed})
		}
		if err := st.Save(&r); err != nil {
			t.Fatal(err)
		}
	}
	for round := range 10 {
		release := make(chan struct{})
		m := &Scans{Service: newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)}), Store: st}
		listed := make(chan struct{})
		go func() { m.List(); close(listed) }()             // loads 50 reports, slowly
		time.Sleep(time.Duration(round) * time.Millisecond) // start at different points of that load
		s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		<-listed
		if got, ok := m.Get(s.ID); !ok || got.Status != ScanRunning {
			t.Fatalf("round %d: the running scan was dropped: %+v", round, got)
		}
		if err := m.Stop(s.ID); err != nil {
			t.Fatal(err)
		}
		if done := waitFor(t, m, s.ID, finished); done.Status != ScanStopped {
			t.Fatalf("round %d: stop didn't reach the scan: %+v", round, done)
		}
		close(release)
	}
}

func TestFindingTimelines(t *testing.T) {
	const noTelnetXML = `<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports></ports></host></nmaprun>`
	fid := model.FindingID("127.0.0.1", "telnet-open", 23, "tcp")

	runner := &fakeRunner{xml: []byte(telnetXML)}
	m := &Scans{Service: newTestService(runner), Store: openStore(t, t.TempDir())}
	runOne := func(ports, xml string) Scan {
		runner.xml = []byte(xml)
		s, err := m.Start(NewScan{Kind: "custom", Settings: ScanRequest{Target: "127.0.0.1", Ports: ports}})
		if err != nil {
			t.Fatal(err)
		}
		return waitFor(t, m, s.ID, finished)
	}

	s1 := runOne("23", telnetXML)
	runOne("22", telnetXML) // other ports, excluded from timeline
	s3 := runOne("23", noTelnetXML)
	s4 := runOne("23", telnetXML)

	got := m.FindingTimelines(s4.ID, []string{fid})
	tl, ok := got[fid]
	if !ok {
		t.Fatalf("missing timeline for %s: %+v", fid, got)
	}
	if !tl.Reopened || tl.ReopenCount != 1 || len(tl.Entries) != 3 {
		t.Fatalf("unexpected timeline: %+v", tl)
	}
	if tl.Entries[0].State != diff.StateOpen || tl.Entries[1].State != diff.StateFixed || tl.Entries[2].State != diff.StateReopened {
		t.Errorf("states: %+v", tl.Entries)
	}
	if strconv.FormatInt(tl.Entries[0].ScanID, 10) != s1.ID || strconv.FormatInt(tl.Entries[1].ScanID, 10) != s3.ID || strconv.FormatInt(tl.Entries[2].ScanID, 10) != s4.ID {
		t.Errorf("scan IDs: %+v", tl.Entries)
	}
	if empty := m.FindingTimelines(s4.ID, nil); len(empty) != 0 {
		t.Errorf("empty findingIDs: %+v", empty)
	}
	for _, id := range []string{"999", "not-an-id"} {
		if missing := m.FindingTimelines(id, []string{fid}); len(missing) != 0 {
			t.Errorf("bad scan %q: %+v", id, missing)
		}
	}
	if noStore := (&Scans{}).FindingTimelines(s4.ID, []string{fid}); len(noStore) != 0 {
		t.Errorf("without store: %+v", noStore)
	}
	m.Store.Close()
	if closed := m.FindingTimelines(s4.ID, []string{fid}); len(closed) != 0 {
		t.Errorf("closed store: %+v", closed)
	}
}

func TestDeleteScan(t *testing.T) {
	t.Run("with store", func(t *testing.T) {
		st := openStore(t, t.TempDir())
		m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, Keep: 1}
		s1, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, m, s1.ID, finished)
		s2, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, m, s2.ID, finished)

		// Another server's running scan in SQLite cannot be deleted.
		otherRunning := store.Run{Name: "elsewhere", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: time.Now()}
		if err := st.Create(&otherRunning); err != nil {
			t.Fatal(err)
		}
		if err := m.Delete(strconv.FormatInt(otherRunning.ID, 10)); err != ErrRunning {
			t.Fatalf("delete store running scan: got %v, want ErrRunning", err)
		}

		// Our own running scan cannot be deleted until stopped.
		release := make(chan struct{})
		m.Service = newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)})
		s3, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Delete(s3.ID); err != ErrRunning {
			t.Fatalf("delete running scan: got %v, want ErrRunning", err)
		}

		// Evicted older scan (s1) and in-memory finished scan (s2) both delete cleanly.
		if err := m.Delete(s1.ID); err != nil {
			t.Fatalf("delete older saved scan: %v", err)
		}
		if _, ok := m.Get(s1.ID); ok {
			t.Error("deleted older scan still found")
		}
		if err := m.Delete(s2.ID); err != nil {
			t.Fatalf("delete in-memory scan: %v", err)
		}
		if _, ok := m.Get(s2.ID); ok {
			t.Error("deleted scan still found")
		}
		for _, id := range []string{"999", "abc", "0"} {
			if err := m.Delete(id); err != ErrNotFound {
				t.Errorf("delete %q: got %v, want ErrNotFound", id, err)
			}
		}

		// Stopping s3 lets it be deleted.
		if err := m.Stop(s3.ID); err != nil {
			t.Fatal(err)
		}
		waitFor(t, m, s3.ID, finished)
		close(release)

		// Deleting directly from the store (like "nuqs delete" from the CLI)
		// is picked up by Get, List and Delete without waiting for a restart.
		id3, _ := strconv.ParseInt(s3.ID, 10, 64)
		if err := st.Delete(id3); err != nil {
			t.Fatalf("external store delete: %v", err)
		}
		if _, ok := m.Get(s3.ID); ok {
			t.Error("externally deleted scan still returned by Get")
		}
		if err := m.Delete(s3.ID); err != ErrNotFound {
			t.Errorf("delete externally deleted scan: got %v, want ErrNotFound", err)
		}
		for _, s := range m.List() {
			if s.ID == s3.ID {
				t.Error("externally deleted scan still in List")
			}
		}

		// Delete a normal stopped scan through Scans.Delete too.
		release2 := make(chan struct{})
		m.Service = newTestService(&blockingRunner{release: release2, xml: []byte(telnetXML)})
		s4, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Stop(s4.ID); err != nil {
			t.Fatal(err)
		}
		waitFor(t, m, s4.ID, finished)
		close(release2)
		if err := m.Delete(s4.ID); err != nil {
			t.Fatalf("delete stopped scan: %v", err)
		}

		st.Close()
		if err := m.Delete(s4.ID); err == nil {
			t.Error("delete on closed store should fail")
		}
	})

	t.Run("in memory", func(t *testing.T) {
		release := make(chan struct{})
		m := &Scans{Service: newTestService(&blockingRunner{release: release, xml: []byte(telnetXML)})}
		s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Delete(s.ID); err != ErrRunning {
			t.Fatalf("delete running in-memory scan: got %v, want ErrRunning", err)
		}
		close(release)
		waitFor(t, m, s.ID, finished)
		if err := m.Delete(s.ID); err != nil {
			t.Fatalf("delete finished in-memory scan: %v", err)
		}
		if _, ok := m.Get(s.ID); ok {
			t.Error("deleted in-memory scan still present")
		}
		if err := m.Delete(s.ID); err != ErrNotFound {
			t.Errorf("delete twice: got %v, want ErrNotFound", err)
		}
	})
}

func TestMaxSavedPrunesOldestScans(t *testing.T) {
	t.Run("prunes oldest beyond MaxSaved and keeps running scans", func(t *testing.T) {
		st := openStore(t, t.TempDir())
		m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, Keep: 10, MaxSaved: 2}
		runOne := func(name string) Scan {
			s, err := m.Start(NewScan{Name: name, Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
			if err != nil {
				t.Fatal(err)
			}
			return waitFor(t, m, s.ID, finished)
		}

		s1 := runOne("one")
		s2 := runOne("two")
		// A running scan from another process must survive pruning.
		other := store.Run{Name: "elsewhere", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: time.Now()}
		if err := st.Create(&other); err != nil {
			t.Fatal(err)
		}
		s3 := runOne("three")

		if _, ok := m.Get(s1.ID); ok {
			t.Error("oldest scan should have been pruned")
		}
		if _, err := st.Run(1); err != store.ErrNotFound {
			t.Errorf("store still has pruned scan 1: %v", err)
		}
		if _, err := st.Run(other.ID); err != nil {
			t.Errorf("running scan in another process was deleted: %v", err)
		}
		list := m.List()
		if len(list) != 2 || list[0].ID != s3.ID || list[1].ID != s2.ID {
			t.Fatalf("kept list = %+v, want [%s, %s]", list, s3.ID, s2.ID)
		}
	})

	t.Run("zero keeps all", func(t *testing.T) {
		st := openStore(t, t.TempDir())
		m := &Scans{Service: newTestService(&fakeRunner{xml: []byte(telnetXML)}), Store: st, MaxSaved: 0}
		for range 4 {
			s, err := m.Start(NewScan{Kind: "quick", Settings: ScanRequest{Target: "127.0.0.1"}})
			if err != nil {
				t.Fatal(err)
			}
			waitFor(t, m, s.ID, finished)
		}
		runs, err := st.Runs(0)
		if err != nil || len(runs) != 4 {
			t.Fatalf("MaxSaved=0 should keep all 4 runs, got %d (%v)", len(runs), err)
		}
	})
}
