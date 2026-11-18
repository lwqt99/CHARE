// Package projectpath locates the synced CHARE source tree independently of
// the working directory chosen by an IDE.
package projectpath

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FindRoot checks each starting directory and its ancestors. The CHARE child
// also supports opening the module from a parent workspace in GoLand.
func FindRoot(starts ...string) (string, error) {
	for _, start := range starts {
		if start == "" {
			continue
		}
		current, err := filepath.Abs(start)
		if err != nil {
			continue
		}
		for {
			for _, dir := range []string{current, filepath.Join(current, "CHARE")} {
				data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
				if err != nil {
					continue
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.TrimSpace(line) == "module example.org/chare" {
						return dir, nil
					}
				}
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	return "", errors.New("CHARE source directory not found; run from the synced CHARE project or specify an absolute -out path")
}

// Root prefers the source compiled into this executable. An executable kept
// inside the project or a project working directory also supports -trimpath
// builds and source trees that were moved after compilation.
func Root() (string, error) {
	var starts []string
	if _, source, _, ok := runtime.Caller(0); ok && filepath.IsAbs(source) {
		starts = append(starts, filepath.Dir(source))
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	return FindRoot(starts...)
}

// OutputRoot anchors default and relative paths to the project, never an
// unrelated IDE working directory. Explicit absolute destinations are retained.
func OutputRoot(out string) (string, error) {
	if filepath.IsAbs(out) {
		return filepath.Clean(out), nil
	}
	root, err := Root()
	if err != nil {
		return "", err
	}
	if out == "" {
		out = "results"
	}
	return filepath.Join(root, out), nil
}
