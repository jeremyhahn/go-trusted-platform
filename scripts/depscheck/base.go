package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

// baseReader reads a module's go.mod as it was at the merge base. found is
// false when the commit has no go.mod in that directory: the change adds
// the module, so every requirement in it is added too.
type baseReader interface {
	GoModAt(dir, commit string) (data []byte, found bool, err error)
}

// gitBase is the baseReader that runs git. safe.directory=* because CI runs
// it in a container whose user does not own the checkout.
type gitBase struct {
	path string
}

func (g gitBase) git(dir string, args ...string) ([]byte, error) {
	path := g.path
	if path == "" {
		path = "git"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, append([]string{"-c", "safe.directory=*", "-C", dir}, args...)...) //#nosec G204 -- the commit comes from CI's merge base, the dir from the Makefile
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &BaseError{Dir: dir, Commit: strings.Join(args, " "), Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

func (g gitBase) GoModAt(dir, commit string) ([]byte, bool, error) {
	if _, err := g.git(dir, "rev-parse", "--verify", "--quiet", commit+"^{commit}"); err != nil {
		var be *BaseError
		if errors.As(err, &be) {
			be.Commit = commit
		}
		return nil, false, err
	}
	// ls-tree paths are relative to dir, so this names dir's own go.mod.
	listed, err := g.git(dir, "ls-tree", "--name-only", commit, "--", "go.mod")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(string(listed)) == "" {
		return nil, false, nil
	}
	data, err := g.git(dir, "show", commit+":./go.mod")
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// baseVersions maps each dependency's module to the path@version it had at
// the merge base.
func baseVersions(file string, data []byte) (map[string]string, error) {
	directives, err := parseGoMod(file, data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, d := range dependencies(file, directives) {
		out[d.Kind+" "+d.Module] = d.Path + "@" + d.Version
	}
	return out, nil
}

// touched reports whether the change adds dep or changes its version or
// path. A nil base (the module is new) touches everything.
func touched(dep dependency, base map[string]string) bool {
	if base == nil {
		return true
	}
	was, ok := base[dep.Kind+" "+dep.Module]
	return !ok || was != dep.Path+"@"+dep.Version
}
