// Tests for saving and loading scans, history lists and migrations.

package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

// Loaded times are local, so the sample is too, then the JSON matches in any time zone.
var at = time.Date(2026, 11, 23, 10, 0, 0, 123456789, time.Local)

func sampleReport() *engine.Report {
	return &engine.Report{
		Targets:  []string{"10.0.0.1", "10.0.0.2"},
		Started:  at,
		Finished: at.Add(3 * time.Second),
		Hosts: []model.Host{
			{Address: "10.0.0.2", Hostnames: []string{"nas.lan"}, Services: []model.Service{
				{Port: 22, Protocol: "tcp", Name: "ssh", Product: "OpenSSH", Version: "7.4"},
				{Port: 443, Protocol: "tcp", Name: "https", Tunnel: "ssl", Guessed: true},
			}},
			{Address: "10.0.0.1"}, // no services, no names
		},
		Findings: []model.Finding{
			{ID: model.FindingID("10.0.0.2", "telnet-open", 23, "tcp"), CheckID: "telnet-open", Title: "Telnet", Severity: model.Medium,
				Confidence: model.Confirmed, Host: "10.0.0.2", Port: 23, Protocol: "tcp", Evidence: "banner", Fix: "turn it off"},
			{ID: "x", CheckID: "redis-no-auth", Title: "Redis", Severity: model.Critical, Confidence: model.Inferred, Host: "10.0.0.1", Port: 6379, Protocol: "tcp"},
			{ID: "y", CheckID: "ssh-password-auth", Title: "SSH", Severity: model.Medium, Confidence: model.Confirmed, Host: "10.0.0.2", Port: 22, Protocol: "tcp"},
		},
		Errors: []engine.CheckError{{CheckID: "ftp-anonymous-login", Host: "10.0.0.2", Port: 21, Error: "timed out"}},
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSaveAndLoadGiveTheSameReport(t *testing.T) {
	s, _ := open(t)
	rep := sampleReport()
	r := Run{Name: "Lab", Description: "the docker lab", Kind: "full", Settings: `{"target":"10.0.0.1-2"}`,
		Targets: rep.Targets, Status: Completed, Error: "1 check failed", Started: at, Finished: at.Add(4 * time.Second), Report: rep}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	if r.ID != 1 {
		t.Fatalf("first ID = %d", r.ID)
	}
	got, err := s.Run(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if asJSON(t, got.Report) != asJSON(t, rep) {
		t.Errorf("report changed on the way through the store:\n got %s\nwant %s", asJSON(t, got.Report), asJSON(t, rep))
	}
	got.Report, r.Report = nil, nil
	if asJSON(t, got) != asJSON(t, r) {
		t.Errorf("run changed:\n got %s\nwant %s", asJSON(t, got), asJSON(t, r))
	}
	if !got.Started.Equal(at) {
		t.Errorf("nanoseconds lost: %v", got.Started)
	}
}

func TestEmptyReportStaysEmpty(t *testing.T) {
	s, _ := open(t)
	rep := &engine.Report{Targets: []string{"10.0.0.9"}, Started: at, Finished: at, Findings: []model.Finding{}, Errors: []engine.CheckError{}}
	r := Run{Name: "Nothing up", Kind: "cli", Targets: rep.Targets, Status: Completed, Started: at, Report: rep}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Same JSON as a fresh report: no hosts is null, no findings is [].
	if asJSON(t, got.Report) != asJSON(t, rep) {
		t.Errorf("got %s, want %s", asJSON(t, got.Report), asJSON(t, rep))
	}
	if !got.Finished.IsZero() || got.Settings != "{}" {
		t.Errorf("defaults: finished %v, settings %q", got.Finished, got.Settings)
	}
}

func TestCreateThenFinish(t *testing.T) {
	s, _ := open(t)
	r := Run{Name: "Live", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: at}
	if err := s.Create(&r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(r.ID)
	if err != nil || got.Status != Running || got.Report != nil {
		t.Fatalf("while running: %+v, %v", got, err)
	}

	r.Status, r.Finished, r.Report = Completed, at.Add(time.Second), sampleReport()
	if err := s.Finish(r); err != nil {
		t.Fatal(err)
	}
	got, err = s.Run(r.ID)
	if err != nil || got.Status != Completed || got.Report == nil || len(got.Report.Findings) != 3 {
		t.Fatalf("after finish: %+v, %v", got, err)
	}

	if err := s.Finish(Run{ID: 99, Status: Completed}); !errors.Is(err, ErrNotFound) {
		t.Errorf("finishing a run that isn't saved: %v", err)
	}
}

func TestFailedRunHasNoReport(t *testing.T) {
	s, _ := open(t)
	r := Run{Name: "Broken", Kind: "quick", Targets: []string{"10.0.0.1"}, Status: Failed, Error: "Nmap isn't installed", Started: at}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(r.ID)
	if err != nil || got.Report != nil || got.Error != "Nmap isn't installed" {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestRunsNewestFirstWithCounts(t *testing.T) {
	s, _ := open(t)
	for _, name := range []string{"first", "second", "third"} {
		r := Run{Name: name, Kind: "cli", Targets: []string{"10.0.0.1"}, Status: Completed, Started: at, Report: sampleReport()}
		if name == "second" {
			r.Status, r.Report = Failed, nil
		}
		if err := s.Save(&r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Runs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Name != "third" || all[2].Name != "first" {
		t.Fatalf("order: %+v", all)
	}
	third := all[0]
	if third.Hosts != 2 || third.Findings != [5]int{0, 0, 2, 0, 1} || third.Targets[0] != "10.0.0.1" || !third.Started.Equal(at) {
		t.Errorf("summary: %+v", third)
	}
	if all[1].Hosts != 0 || all[1].Findings != [5]int{} || all[1].Status != Failed {
		t.Errorf("failed run summary: %+v", all[1])
	}
	if two, _ := s.Runs(2); len(two) != 2 || two[1].Name != "second" {
		t.Errorf("limit: %+v", two)
	}
}

func TestRunNotFound(t *testing.T) {
	s, _ := open(t)
	if _, err := s.Run(42); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v", err)
	}
}

func TestCloseUnfinished(t *testing.T) {
	s, _ := open(t)
	r := Run{Name: "cut off", Kind: "quick", Targets: []string{"10.0.0.1"}, Started: at}
	if err := s.Create(&r); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseUnfinished(); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Run(r.ID)
	if got.Status != Stopped || got.Error == "" || !got.Finished.Equal(at) {
		t.Errorf("%+v", got)
	}
}

func TestReopenKeepsDataAndSkipsDoneMigrations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := Run{Name: "kept", Kind: "cli", Targets: []string{"10.0.0.1"}, Status: Completed, Started: at, Report: sampleReport()}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Errorf("user_version = %d", version)
	}
	if got, err := s.Run(r.ID); err != nil || got.Name != "kept" {
		t.Errorf("after reopening: %+v, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dir, "nuqs.db")); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("database file mode: %v, %v", info, err)
		}
	}
}

func TestOddFolderNames(t *testing.T) {
	// "?", "#" and "%" mean something in a SQLite URI, spaces are normal on macOS.
	for _, name := range []string{"Application Support", "we#ird", "q?mark", "100% sure", "a%3Fb"} {
		if runtime.GOOS == "windows" && strings.Contains(name, "?") {
			continue
		}
		dir := filepath.Join(t.TempDir(), name)
		s, err := Open(dir)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		r := Run{Name: name, Kind: "cli", Targets: []string{"x"}, Status: Completed, Started: at}
		if err := s.Save(&r); err != nil {
			t.Fatal(err)
		}
		s.Close()
		entries, _ := os.ReadDir(filepath.Dir(dir))
		if len(entries) != 1 || entries[0].Name() != name {
			t.Errorf("%q: the database went somewhere else: %v", name, entries)
		}
		s, err = Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.Run(1); err != nil || got.Name != name {
			t.Errorf("%q: reopened %+v, %v", name, got, err)
		}
		s.Close()
	}
}

func TestDatabaseFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use POSIX file permission bits")
	}
	s, dir := open(t)
	r := Run{Name: "x", Kind: "cli", Targets: []string{"x"}, Status: Completed, Started: at, Report: sampleReport()}
	if err := s.Save(&r); err != nil {
		t.Fatal(err)
	}
	// While it's open, the WAL files hold scan data too.
	for _, name := range []string{"nuqs.db", "nuqs.db-wal", "nuqs.db-shm"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", name, info.Mode().Perm())
		}
	}
}

func TestNewerDatabaseIsRefused(t *testing.T) {
	_, dir := open(t)
	s, _ := Open(dir)
	s.db.Exec(`PRAGMA user_version = 999`)
	s.Close()
	if _, err := Open(dir); err == nil {
		t.Error("a database from a newer Nuqs should be refused")
	}
}

func TestBadMigrationRollsBack(t *testing.T) {
	old := migrations
	t.Cleanup(func() { migrations = old })
	migrations = append(append([]string{}, old...), `CREATE TABLE extra (x INTEGER); THIS IS NOT SQL;`)
	dir := t.TempDir()
	if _, err := Open(dir); err == nil {
		t.Fatal("a broken migration should fail")
	}
	migrations = old
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'extra'`).Scan(&n)
	if n != 0 {
		t.Error("half a migration was kept")
	}
}

func TestOpenErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := Open(filepath.Join(file, "sub")); err == nil {
		t.Error("a data folder inside a file should fail")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nuqs.db"), []byte("this is not a database, just some text that is long enough"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Error("a file that isn't SQLite should fail")
	}
}

func TestDefaultDir(t *testing.T) {
	t.Setenv("NUQS_DATA_DIR", "/tmp/somewhere")
	if got := DefaultDir(); got != "/tmp/somewhere" {
		t.Errorf("got %q", got)
	}
	t.Setenv("NUQS_DATA_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/cfg")
	t.Setenv("HOME", "/tmp/home")
	if got := DefaultDir(); filepath.Base(got) != "nuqs" {
		t.Errorf("got %q", got)
	}
}

func TestSaveAfterCloseFails(t *testing.T) {
	s, _ := open(t)
	s.Close()
	r := Run{Name: "late", Kind: "cli", Targets: []string{"x"}, Started: at}
	if err := s.Save(&r); err == nil {
		t.Error("save on a closed store should fail")
	}
	if _, err := s.Runs(0); err == nil {
		t.Error("list on a closed store should fail")
	}
	if _, err := s.Run(1); err == nil {
		t.Error("load on a closed store should fail")
	}
	if err := s.CloseUnfinished(); err == nil {
		t.Error("close unfinished on a closed store should fail")
	}
	if err := s.Finish(Run{ID: 1}); err == nil {
		t.Error("finish on a closed store should fail")
	}
	if err := s.Delete(1); err == nil {
		t.Error("delete on a closed store should fail")
	}
	if _, err := s.Prune(1); err == nil {
		t.Error("prune on a closed store should fail")
	}
	if n, err := s.Prune(0); err != nil || n != 0 {
		t.Errorf("prune 0 on a closed store should be a no-op: n=%d err=%v", n, err)
	}
}

func TestDeleteRunAndCascade(t *testing.T) {
	s, _ := open(t)
	r1 := Run{Name: "first", Kind: "cli", Targets: []string{"10.0.0.1", "10.0.0.2"}, Status: Completed, Started: at, Finished: at.Add(time.Minute), Report: sampleReport()}
	r2 := Run{Name: "second", Kind: "cli", Targets: []string{"10.0.0.1", "10.0.0.2"}, Status: Completed, Started: at.Add(time.Hour), Finished: at.Add(61 * time.Minute), Report: sampleReport()}
	running := Run{Name: "live", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: at.Add(2 * time.Hour)}
	if err := s.Save(&r1); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&r2); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(&running); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(running.ID); !errors.Is(err, ErrRunning) {
		t.Fatalf("delete running: got %v, want ErrRunning", err)
	}
	if err := s.Delete(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: got %v, want ErrNotFound", err)
	}
	if err := s.Delete(r1.ID); err != nil {
		t.Fatalf("delete completed: %v", err)
	}
	if _, err := s.Run(r1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted run still loads: %v", err)
	}
	for _, table := range []string{"hosts", "services", "findings", "check_errors"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE run_id = ?`, r1.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows for deleted run %d", table, n, r1.ID)
		}
	}
	got2, err := s.Run(r2.ID)
	if err != nil || got2.Report == nil || len(got2.Report.Hosts) != 2 || len(got2.Report.Findings) != 3 || len(got2.Report.Errors) != 1 {
		t.Fatalf("unrelated run was affected: %+v, %v", got2, err)
	}
}

func TestPruneOldestScansAndCascade(t *testing.T) {
	s, _ := open(t)
	runs := []Run{
		{Name: "first", Kind: "cli", Targets: []string{"10.0.0.1"}, Status: Completed, Started: at, Finished: at.Add(time.Minute), Report: sampleReport()},
		{Name: "second", Kind: "cli", Targets: []string{"10.0.0.2"}, Status: Stopped, Started: at.Add(time.Hour), Finished: at.Add(61 * time.Minute), Report: sampleReport()},
		{Name: "third", Kind: "quick", Targets: []string{"10.0.0.3"}, Status: Failed, Error: "nmap failed", Started: at.Add(2 * time.Hour), Finished: at.Add(2 * time.Hour)},
		{Name: "fourth", Kind: "cli", Targets: []string{"10.0.0.4"}, Status: Completed, Started: at.Add(3 * time.Hour), Finished: at.Add(181 * time.Minute), Report: sampleReport()},
	}
	for i := range runs {
		if err := s.Save(&runs[i]); err != nil {
			t.Fatal(err)
		}
	}
	running := Run{Name: "live", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: at.Add(4 * time.Hour)}
	if err := s.Create(&running); err != nil {
		t.Fatal(err)
	}

	// 0, negative, and limits >= count do nothing.
	for _, keep := range []int{0, -5, 4, 10} {
		if n, err := s.Prune(keep); err != nil || n != 0 {
			t.Fatalf("Prune(%d): got (%d, %v), want (0, nil)", keep, n, err)
		}
	}

	// Keeping 2 removes the oldest 2 non-running runs and leaves the running scan intact.
	n, err := s.Prune(2)
	if err != nil || n != 2 {
		t.Fatalf("Prune(2): got (%d, %v), want (2, nil)", n, err)
	}
	for _, pruned := range []int64{runs[0].ID, runs[1].ID} {
		if _, err := s.Run(pruned); !errors.Is(err, ErrNotFound) {
			t.Errorf("pruned run %d still loads: %v", pruned, err)
		}
		for _, table := range []string{"hosts", "services", "findings", "check_errors"} {
			var count int
			if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE run_id = ?`, pruned).Scan(&count); err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			if count != 0 {
				t.Errorf("%s still has %d rows for pruned run %d", table, count, pruned)
			}
		}
	}
	for _, kept := range []int64{runs[2].ID, runs[3].ID, running.ID} {
		if _, err := s.Run(kept); err != nil {
			t.Errorf("kept run %d missing: %v", kept, err)
		}
	}
	got4, err := s.Run(runs[3].ID)
	if err != nil || got4.Report == nil || len(got4.Report.Hosts) != 2 || len(got4.Report.Findings) != 3 || len(got4.Report.Errors) != 1 {
		t.Fatalf("kept run 4 corrupted: %+v, %v", got4, err)
	}

	// Once the running scan finishes, pruning to 2 removes run 3 and keeps run 4 and the newly finished run.
	running.Status, running.Finished, running.Report = Completed, at.Add(4*time.Hour+time.Minute), sampleReport()
	if err := s.Finish(running); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Prune(2); err != nil || n != 1 {
		t.Fatalf("Prune(2) after finish: got (%d, %v), want (1, nil)", n, err)
	}
	if _, err := s.Run(runs[2].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("run 3 should be pruned: %v", err)
	}
	list, err := s.Runs(0)
	if err != nil || len(list) != 2 || list[0].ID != running.ID || list[1].ID != runs[3].ID {
		t.Fatalf("remaining runs = %+v, err=%v", list, err)
	}
}

// Regression: a report that can't be written must not leave a finished run
// behind without it. Save is one transaction.
func TestSaveIsAllOrNothing(t *testing.T) {
	s, _ := open(t)
	// Make the findings insert fail halfway through the save.
	if _, err := s.db.Exec(`CREATE TRIGGER no_findings BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	r := Run{Name: "half", Kind: "cli", Targets: []string{"10.0.0.1"}, Status: Completed, Started: at, Report: sampleReport()}
	if err := s.Save(&r); err == nil {
		t.Fatal("save should fail")
	}
	runs, err := s.Runs(0)
	if err != nil || len(runs) != 0 {
		t.Errorf("a failed save left %d runs behind: %+v, %v", len(runs), runs, err)
	}
}

// Regression: several Nuqs processes opening a new database at once must
// not run the same migration twice ("table runs already exists").
func TestParallelFirstOpens(t *testing.T) {
	for round := range 20 {
		dir := t.TempDir()
		errs := make(chan error, 8)
		for range 8 {
			go func() {
				s, err := Open(dir)
				if err == nil {
					_, err = s.Runs(0)
					s.Close()
				}
				errs <- err
			}()
		}
		for range 8 {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
}
