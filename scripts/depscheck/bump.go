package main

import (
	"fmt"
	"io"
)

// bumpable reports whether -bump moves this finding: a require behind its
// latest, with no reason comment, past the fresh window, looked up, used,
// and not a fork onto another module path.
func bumpable(f finding) bool {
	d := f.Dep
	return f.Lookup == nil && !f.Unused && f.Behind && !f.Fresh &&
		d.Reason == "" && d.Path == d.Module && f.Latest != forkLatest
}

// bumpModule runs `go get path@latest` for each bumpable require in dir,
// then `go mod tidy`, and prints each move. A replace that would move is
// printed as a hand edit, since go get does not rewrite a replace.
func bumpModule(edit moduleEditor, dir string, findings []finding, stdout io.Writer) error {
	moved := 0
	for _, f := range findings {
		if !bumpable(f) {
			continue
		}
		d := f.Dep
		if d.Kind == kindReplace {
			if _, err := fmt.Fprintf(stdout, "%s:%d: replace %s %s -> %s needs a hand edit\n", d.File, d.Line, d.Module, d.Version, f.Latest); err != nil {
				return err
			}
			continue
		}
		if err := edit.Get(dir, d.Path+"@"+f.Latest); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "bumped %s %s -> %s\n", d.Path, d.Version, f.Latest); err != nil {
			return err
		}
		moved++
	}
	if moved == 0 {
		return nil
	}
	return edit.Tidy(dir)
}
