package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// vulnScanner reports the module versions govulncheck finds vulnerable in
// a module directory, keyed path@version, with the advisories for each.
type vulnScanner interface {
	Scan(dir string) (map[string][]advisory, error)
}

// advisory is one govulncheck finding against a module version.
type advisory struct {
	ID    string
	Fixed string
}

// govulncheck is the vulnScanner that runs govulncheck at module level:
// every vulnerable version in the build list counts, reachable or not.
type govulncheck struct {
	path   string
	goPath string
	tags   string
}

func (g govulncheck) Scan(dir string) (map[string][]advisory, error) {
	path := g.path
	if path == "" {
		path = "govulncheck"
	}
	goPath := g.goPath
	if goPath == "" {
		goPath = "go"
	}
	run, err := scanDir(goPath, g.tags, dir)
	if err != nil {
		return nil, err
	}
	args := []string{"-scan", "module", "-format", "json"}
	if g.tags != "" {
		args = append(args, "-tags", g.tags)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, args...) //#nosec G204 -- the scanner and the tags come from the Makefile
	cmd.Dir = run
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &VulnError{Dir: dir, Stderr: stderr.String(), Err: err}
	}
	return decodeVulns(dir, &stdout)
}

// vulnMessage is the part of one govulncheck JSON message deps-check reads.
type vulnMessage struct {
	Config *struct {
		ScanLevel string `json:"scan_level"`
	} `json:"config"`
	Finding *struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module  string `json:"module"`
			Version string `json:"version"`
		} `json:"trace"`
	} `json:"finding"`
}

// errNoConfig is returned when the stream has no config message: whatever
// printed it was not a govulncheck scan.
var errNoConfig = errors.New("no config message in the output")

// decodeVulns decodes the stream of JSON messages govulncheck -format json
// prints. The first trace frame of a finding is the vulnerable module.
func decodeVulns(dir string, r io.Reader) (map[string][]advisory, error) {
	out := make(map[string][]advisory)
	seen := make(map[string]bool)
	config := false
	dec := json.NewDecoder(r)
	for {
		var m vulnMessage
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, &VulnError{Dir: dir, Err: err}
		}
		if m.Config != nil {
			config = true
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		f := m.Finding
		key := f.Trace[0].Module + "@" + f.Trace[0].Version
		if seen[key+" "+f.OSV] {
			continue
		}
		seen[key+" "+f.OSV] = true
		out[key] = append(out[key], advisory{ID: f.OSV, Fixed: f.FixedVersion})
	}
	if !config {
		return nil, &VulnError{Dir: dir, Err: errNoConfig}
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].ID < out[k][j].ID })
	}
	return out, nil
}

// vulnFinding is one vulnerable module version in one module directory.
// Required is true when the module has a require line in that directory's
// go.mod: only then does the finding fail. The standard library, the
// toolchain and a module the build list pulls in with no require line are
// reported, not failed.
type vulnFinding struct {
	Dir        string
	Module     string
	Version    string
	Advisories []advisory
	Required   bool
}

func (v vulnFinding) describe() string {
	s := ""
	for i, a := range v.Advisories {
		if i > 0 {
			s += ", "
		}
		s += a.ID
		if a.Fixed != "" {
			s += " (fixed in " + a.Fixed + ")"
		}
	}
	return s
}

// toolchainModule reports whether govulncheck's module name is the Go
// distribution rather than a module: the toolchain image carries it.
func toolchainModule(mod string) bool {
	return mod == "stdlib" || mod == "toolchain"
}

// note is the reported, not failed, line for a finding that is not a
// requirement.
func (v vulnFinding) note() string {
	if toolchainModule(v.Module) {
		return v.Dir + ": reported, not failed: " + v.Module + " go" + strings.TrimPrefix(v.Version, "v") + ": " + v.describe() +
			", the portfolio-wide toolchain pass carries it (CLAUDE.md Go toolchain rule); the security job gates reachable stdlib findings"
	}
	return v.Dir + ": reported, not failed: " + v.Module + " " + v.Version + ": " + v.describe() +
		", no require line in go.mod (an indirect-only module; the bump of the requirement that pulls it in carries it)"
}

// requiredModules is the set of module paths with a require line, direct
// or // indirect, in the go.mod of dir.
func requiredModules(dir string) (map[string]bool, error) {
	file := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(file) //#nosec G304 -- the go.mod of a module directory the Makefile names
	if err != nil {
		return nil, err
	}
	directives, err := parseGoMod(file, data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, d := range directives {
		if d.Kind == kindRequire {
			out[d.Path] = true
		}
	}
	return out, nil
}

// vulnFindings turns a scan into findings in a stable order, marking each
// one whose module go.mod requires.
func vulnFindings(dir string, hits map[string][]advisory, required map[string]bool) []vulnFinding {
	keys := make([]string, 0, len(hits))
	for k := range hits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]vulnFinding, 0, len(keys))
	for _, k := range keys {
		mod, ver, _ := strings.Cut(k, "@")
		out = append(out, vulnFinding{Dir: dir, Module: mod, Version: ver, Advisories: hits[k], Required: required[mod]})
	}
	return out
}

// scanDir is the directory govulncheck runs in for the module at dir. A
// module scan takes no package pattern and loads the directory it runs in,
// so a module root with no Go files of its own fails with "no Go files".
// Any package directory of the same module reads the same go.mod, so the
// first package `go list ./...` reports with Go files under the current
// build constraints is used; go list already leaves out nested modules,
// testdata and the directories go ignores. A module with no such
// package is scanned at its root, which fails: a module whose every file is
// behind a build tag names that tag in -vuln-tags. Tags do not change what a
// module scan reports, which is the go.mod build list.
func scanDir(goPath, tags, dir string) (string, error) {
	args := []string{"list", "-e"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, err := goCommand{path: goPath}.run(dir, append(args, "-f", "{{if .GoFiles}}{{.Dir}}{{end}}", "./...")...)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line, nil
		}
	}
	return dir, nil
}
