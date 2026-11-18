package projectpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindRootFromParentNestedAndSourceFallback(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "path with spaces")
	root := filepath.Join(parent, "CHARE")
	nested := filepath.Join(root, "internal", "projectpath")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/chare\n\ngo 1.23\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, starts := range [][]string{{parent}, {root}, {nested}, {t.TempDir(), nested}} {
		got, err := FindRoot(starts...)
		if err != nil || got != root {
			t.Fatalf("FindRoot(%v) = %q, %v; want %q", starts, got, err, root)
		}
	}
}

func TestFindRootRejectsDifferentModule(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/chare-other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := FindRoot(root); err == nil {
		t.Fatalf("accepted wrong module %q", got)
	}
}

func TestOutputAndSourceRootIgnoreUnrelatedWorkingDirectory(t *testing.T) {
	// This models a root main.go launched by GoLand with GOPATH/src as its cwd.
	// Do not run this test in parallel: cwd is process-wide on Go 1.23.
	wantRoot, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	unrelated := t.TempDir()
	if err := os.Chdir(unrelated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
	if got, err := Root(); err != nil || got != wantRoot {
		t.Fatalf("source root changed with cwd: %q, %v", got, err)
	}
	absolute := filepath.Join(unrelated, "explicit results")
	for _, tc := range []struct{ out, want string }{
		{"", filepath.Join(wantRoot, "results")},
		{"results", filepath.Join(wantRoot, "results")},
		{"custom results", filepath.Join(wantRoot, "custom results")},
		{absolute, absolute},
	} {
		if got, err := OutputRoot(tc.out); err != nil || got != tc.want {
			t.Errorf("OutputRoot(%q) = %q, %v; want %q", tc.out, got, err, tc.want)
		}
	}
}
