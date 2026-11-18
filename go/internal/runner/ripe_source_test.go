package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceManifestContainsEmbeddedRIPEFixture(t *testing.T) {
	info := sourceSnapshot()
	if info.Status != "recorded" || len(info.Errors) != 0 {
		t.Fatalf("source capture: %+v", info)
	}
	const name = "internal/ripecore/testdata/f.param"
	want, err := hashFile(filepath.Join(info.Root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Files[name] != want {
		t.Fatal("embedded functional parameter omitted or mismatched in source manifest")
	}
}

func TestSourceManifestFromUnrelatedWorkingDirectory(t *testing.T) {
	// GoLand may start root main.go outside the repository. Both the output
	// location and the actual source hashes must still refer to this project.
	before := sourceSnapshot()
	if before.Status != "recorded" {
		t.Fatalf("source capture before cwd change: %+v", before)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
	after := sourceSnapshot()
	if after.Status != "recorded" || after.Root != before.Root || len(after.Files) != len(before.Files) {
		t.Fatalf("source capture changed with cwd: %+v", after)
	}
	for name, hash := range before.Files {
		if after.Files[name] != hash {
			t.Errorf("source hash lost or changed: %s", name)
		}
	}
}

func TestSourceManifestIncludesGoLandLauncher(t *testing.T) {
	info := sourceSnapshot()
	if info.Status != "recorded" {
		t.Fatalf("source capture: %+v", info)
	}
	for _, name := range []string{"cmd/goland/main.go", "cmd/goland/main_test.go", ".run/CHARE Batch.run.xml", ".run/CHARE Sanity.run.xml", ".gitattributes", "internal/projectpath/path.go", "internal/projectpath/path_test.go"} {
		want, err := hashFile(filepath.Join(info.Root, filepath.FromSlash(name)))
		if err != nil || info.Files[name] != want {
			t.Fatalf("launcher input omitted: %s (%v)", name, err)
		}
	}
}
