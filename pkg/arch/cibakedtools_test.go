// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package arch

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The CI runner image bakes the Go analysis tools at pinned versions (#98).
// A workflow step that `go install`s one of them again is a redundant network
// call, and a live source of flakes: sum.golang.org resolves to an IPv6
// address the runner hosts cannot route, so the install fails whenever Go's
// v6 -> v4 fallback does not complete. A version bump is a rebuild of the
// image (agent-company owns its pins), never a `go install` added back here.
//
// Only workflow `run:` steps are checked. A Makefile target that builds its
// own pinned copy (install-golangci-lint builds GOLANGCI_LINT_VERSION, which
// the image does not bake) is the Makefile's contract, not a workflow install.

// bakedTool is one tool the runner image installs, as its manifest
// (/etc/ci-runner-tools.txt in the image, quoted in #98) lists it.
type bakedTool struct {
	Name    string
	Package string
	Version string
}

var bakedRunnerTools = []bakedTool{
	{Name: "golangci-lint", Package: "github.com/golangci/golangci-lint/v2/cmd/golangci-lint", Version: "v2.12.2"},
	{Name: "gosec", Package: "github.com/securego/gosec/v2/cmd/gosec", Version: "v2.29.0"},
	{Name: "govulncheck", Package: "golang.org/x/vuln/cmd/govulncheck", Version: "v1.7.0"},
	{Name: "staticcheck", Package: "honnef.co/go/tools/cmd/staticcheck", Version: "2025.1.1"},
	{Name: "actionlint", Package: "github.com/rhysd/actionlint/cmd/actionlint", Version: "v1.7.7"},
	{Name: "protoc-gen-go", Package: "google.golang.org/protobuf/cmd/protoc-gen-go", Version: "v1.36.6"},
}

// bakedToolInstallKept names the baked tools a workflow still installs over
// the network, each with the reason the baked copy cannot serve yet. An entry
// whose install is gone is itself a finding, so the list only shrinks. It is
// empty since the security runner job folded into the image job (#927): make
// security runs the image's baked govulncheck there.
var bakedToolInstallKept = map[string]string{}

// goInstallRe matches `go install [flags] <package>@<version>` in a script line.
var goInstallRe = regexp.MustCompile(`\bgo\s+install\s+(?:-\S+\s+)*([^\s@]+)@(\S+)`)

// BakedToolInstallError reports a workflow that installs a baked tool over
// the network, or a kept install that no workflow performs any more.
type BakedToolInstallError struct {
	// File is the repo-relative workflow file, or empty for a stale keep.
	File string

	// Line is the 1-based line in File, or 0 when unknown.
	Line int

	// Package is the Go package path the finding is about.
	Package string

	// Reason says what is wrong and what fixes it.
	Reason string
}

func (e BakedToolInstallError) Error() string {
	return fmt.Sprintf("%s:%d: %s: %s", e.File, e.Line, e.Package, e.Reason)
}

// goInstall is one `go install` found in a workflow step.
type goInstall struct {
	Line    int
	Package string
	Version string
}

// workflowGoInstalls returns every `go install` in wf's run steps, in file order.
func workflowGoInstalls(wf ciWorkflow) []goInstall {
	var installs []goInstall
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			for offset, line := range strings.Split(step.Run, "\n") {
				m := goInstallRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				installs = append(installs, goInstall{Line: step.RunLine + offset, Package: m[1], Version: m[2]})
			}
		}
	}
	return installs
}

// bakedToolInstallFindings reports each install in wf of a baked tool that
// bakedToolInstallKept does not justify.
func bakedToolInstallFindings(wf ciWorkflow, kept map[string]string) []BakedToolInstallError {
	var findings []BakedToolInstallError
	for _, in := range workflowGoInstalls(wf) {
		i := slices.IndexFunc(bakedRunnerTools, func(t bakedTool) bool { return t.Package == in.Package })
		if i < 0 {
			continue
		}
		if _, ok := kept[in.Package]; ok {
			continue
		}
		tool := bakedRunnerTools[i]
		findings = append(findings, BakedToolInstallError{
			File:    wf.File,
			Line:    in.Line,
			Package: in.Package,
			Reason: fmt.Sprintf("the runner image bakes %s %s; drop this network install of @%s (#98), "+
				"and ask agent-company for an image rebuild if the pin must move", tool.Name, tool.Version, in.Version),
		})
	}
	return findings
}

// staleBakedToolKeeps reports each bakedToolInstallKept entry that no
// workflow installs, given the set of packages the workflows do install.
func staleBakedToolKeeps(kept map[string]string, installed map[string]bool) []BakedToolInstallError {
	var findings []BakedToolInstallError
	for pkg := range kept {
		if !installed[pkg] {
			findings = append(findings, BakedToolInstallError{
				Package: pkg,
				Reason:  "kept in bakedToolInstallKept but no workflow installs it; delete the entry",
			})
		}
	}
	return findings
}

// TestCIWorkflowsDoNotInstallBakedTools is the ratchet on the real workflows.
func TestCIWorkflowsDoNotInstallBakedTools(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, workflowsDir, "*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	installed := map[string]bool{}
	for _, path := range files {
		rel, relErr := filepath.Rel(root, path)
		require.NoError(t, relErr)
		wf := loadCIWorkflow(t, root, rel)
		for _, in := range workflowGoInstalls(wf) {
			installed[in.Package] = true
		}
		for _, finding := range bakedToolInstallFindings(wf, bakedToolInstallKept) {
			t.Error(finding)
		}
	}
	for _, finding := range staleBakedToolKeeps(bakedToolInstallKept, installed) {
		t.Error(finding)
	}
}

// fixtureKept keeps the fixtures' govulncheck install, so they hold a kept
// install apart from a rejected one whatever bakedToolInstallKept holds.
var fixtureKept = map[string]string{
	"golang.org/x/vuln/cmd/govulncheck": "a fixture's kept install",
}

const fixtureBakedInstalls = `on: push
jobs:
  security:
    steps:
      - uses: actions/checkout@v6
      - name: Install gosec
        run: go install github.com/securego/gosec/v2/cmd/gosec@latest
      - name: Install tools
        run: |
          echo installing
          go install -v honnef.co/go/tools/cmd/staticcheck@2025.1.1
      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: Install gocovmerge
        run: go install github.com/wadey/gocovmerge@latest
`

func TestBakedToolInstallFindingsRejectEachBakedInstall(t *testing.T) {
	wf, err := parseCIWorkflow("ci.yml", []byte(fixtureBakedInstalls))
	require.NoError(t, err)

	findings := bakedToolInstallFindings(wf, fixtureKept)
	require.Len(t, findings, 2)

	require.Equal(t, 7, findings[0].Line)
	require.Equal(t, "github.com/securego/gosec/v2/cmd/gosec", findings[0].Package)
	require.Contains(t, findings[0].Error(), "ci.yml:7:")
	require.Contains(t, findings[0].Reason, "bakes gosec v2.29.0")

	require.Equal(t, 11, findings[1].Line, "a block-scalar install points at its own line")
	require.Equal(t, "honnef.co/go/tools/cmd/staticcheck", findings[1].Package)
}

func TestBakedToolInstallFindingsAcceptKeptAndUnbakedInstalls(t *testing.T) {
	data := `jobs:
  security:
    steps:
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: go install github.com/wadey/gocovmerge@latest
      - run: make gosec
`
	wf, err := parseCIWorkflow("ci.yml", []byte(data))
	require.NoError(t, err)

	require.Empty(t, bakedToolInstallFindings(wf, fixtureKept))
	require.Len(t, workflowGoInstalls(wf), 2)
}

func TestStaleBakedToolKeepsRejectAnUnusedEntry(t *testing.T) {
	require.Empty(t, staleBakedToolKeeps(fixtureKept, map[string]bool{"golang.org/x/vuln/cmd/govulncheck": true}))

	findings := staleBakedToolKeeps(fixtureKept, map[string]bool{})
	require.Len(t, findings, 1)
	require.Equal(t, "golang.org/x/vuln/cmd/govulncheck", findings[0].Package)
	require.Contains(t, findings[0].Error(), "delete the entry")
}
