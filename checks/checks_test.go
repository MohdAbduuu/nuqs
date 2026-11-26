// Makes sure every built-in check is valid, tested and listed.

package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nuqs-org/nuqs/internal/check"
)

// Every built-in check must be valid (unique ID, title, description, fix, references and so on).
func TestAllValid(t *testing.T) {
	all := All()
	if err := check.Validate(all); err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		in := c.Info()
		if len(in.References) == 0 {
			t.Errorf("check %q: built-in check must include at least one reference link", in.ID)
		}
	}
}

// Every check folder must have tests, and must be listed in All. This stops
// someone from adding a check and forgetting either part.
func TestEveryCheckHasTestsAndIsListed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	folders := 0
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "testdata" {
			continue
		}
		folders++
		tests, _ := filepath.Glob(filepath.Join(e.Name(), "*_test.go"))
		if len(tests) == 0 {
			t.Errorf("check folder %q has no tests, every check needs positive and negative tests", e.Name())
		}
	}
	if n := len(All()); n != folders {
		t.Errorf("found %d check folders but All() lists %d checks, did you forget to add one to All?", folders, n)
	}
}

// All must return a new slice each time so callers can't change it for others.
func TestAllReturnsFreshSlice(t *testing.T) {
	a := All()
	a[0] = nil
	if All()[0] == nil {
		t.Error("All() shares its slice between callers")
	}
}
