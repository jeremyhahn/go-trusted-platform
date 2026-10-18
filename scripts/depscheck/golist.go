package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
)

// listedModule is the part of one `go list -m -u -versions -json` entry
// deps-check reads.
type listedModule struct {
	Path    string
	Version string
	// Versions is every published version, in semantic-version order, with
	// retracted versions left out.
	Versions []string
	// Update is the go command's own "latest release" answer: set only when
	// it is newer than Version.
	Update *struct{ Version string }
	Error  *struct{ Err string }
}

// moduleSource answers the two questions deps-check asks the go command.
type moduleSource interface {
	GoProxy(dir string) (string, error)
	List(dir string, modules []string) (map[string]listedModule, error)
}

// goCommand is the moduleSource that runs the go command.
type goCommand struct {
	path string
}

func (g goCommand) GoProxy(dir string) (string, error) {
	out, err := g.run(dir, "env", "GOPROXY")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// List runs `go list -m -u -versions -json -e`. -e keeps a failed lookup
// in that module's Error field instead of ending the whole listing.
func (g goCommand) List(dir string, modules []string) (map[string]listedModule, error) {
	out, err := g.run(dir, append([]string{"list", "-m", "-u", "-versions", "-json", "-e"}, modules...)...)
	if err != nil {
		return nil, err
	}
	return decodeList(dir, bytes.NewReader(out))
}

func (g goCommand) run(dir string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(g.path, args...) //#nosec G204 -- the go command comes from the Makefile, the arguments from the go.mod under check
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &GoCommandError{Dir: dir, Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// decodeList decodes the stream of JSON objects `go list -json` prints,
// keyed by module path.
func decodeList(dir string, r io.Reader) (map[string]listedModule, error) {
	modules := make(map[string]listedModule)
	dec := json.NewDecoder(r)
	for {
		var m listedModule
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return modules, nil
		}
		if err != nil {
			return nil, &ListOutputError{Dir: dir, Err: err}
		}
		modules[m.Path] = m
	}
}

// proxyDisabled reports whether a GOPROXY value disables every lookup. Only
// "off" as the first entry does; "off" later in the list is a fallback.
func proxyDisabled(goproxy string) bool {
	entries := strings.FieldsFunc(goproxy, func(r rune) bool { return r == ',' || r == '|' })
	return len(entries) > 0 && strings.TrimSpace(entries[0]) == "off"
}
