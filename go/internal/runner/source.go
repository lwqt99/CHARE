package runner

import (
	"io/fs"
	"os"
	"path/filepath"

	"example.org/chare/internal/projectpath"
)

type sourceInfo struct {
	Status string            `json:"status"`
	Root   string            `json:"source_root,omitempty"`
	Files  map[string]string `json:"sha256_by_relative_path,omitempty"`
	Errors []string          `json:"errors,omitempty"`
}

func sourceSnapshot() sourceInfo {
	info := sourceInfo{Status: "source_tree_unavailable", Files: make(map[string]string)}
	root, err := projectpath.Root()
	if err != nil {
		info.Errors = append(info.Errors, err.Error())
		return info
	}
	info.Root = root
	info.Status = "recorded"
	add := func(path string) {
		rel, e := filepath.Rel(info.Root, path)
		if e != nil {
			info.Errors = append(info.Errors, e.Error())
			return
		}
		h, e := hashFile(path)
		if e != nil {
			info.Errors = append(info.Errors, e.Error())
			return
		}
		info.Files[filepath.ToSlash(rel)] = h
	}
	for _, name := range []string{"main.go", "go.mod", "go.sum", ".gitignore", ".gitattributes", "README.md", "run.sh", "run.ps1"} {
		p := filepath.Join(info.Root, name)
		if _, e := os.Stat(p); e == nil {
			add(p)
		}
	}
	for _, sub := range []string{"internal", "cmd", ".run", "config", "docs", "vendor"} {
		err = filepath.WalkDir(filepath.Join(info.Root, sub), func(path string, entry fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				info.Errors = append(info.Errors, "source symlink not followed: "+path)
				return nil
			}
			// The vendored Go/C wrapper and its headers are executable input too.
			// Record every regular vendor file, including extensionless licenses.
			if sub == "vendor" {
				add(path)
				return nil
			}
			switch filepath.Ext(path) {
			// Public parameter fixtures can be compile-time inputs through go:embed.
			// Include them even though they are not benchmark curve selections.
			case ".go", ".json", ".md", ".param", ".xml":
				add(path)
			}
			return nil
		})
		if err != nil {
			info.Errors = append(info.Errors, err.Error())
		}
	}
	if len(info.Errors) > 0 {
		info.Status = "partial"
	}
	return info
}
