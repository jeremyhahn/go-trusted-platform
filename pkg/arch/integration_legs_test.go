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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	// integrationRunnerPath is the suite runner, repo-relative. Its `legs`
	// argument prints ALL_TARGETS (with compute) and then every leg.
	integrationRunnerPath = "build/docker/devcontainer/" + integrationRunner

	// integrationJobID is the ci.yml job that runs one matrix entry per leg.
	integrationJobID = "integration"
)

// IntegrationLegError reports one way the integration legs fail to split the
// suite (#1119): a target in no leg or in two, a leg target `all` does not
// run, an empty or misnumbered leg, or a ci.yml matrix that does not run
// exactly the runner's legs.
type IntegrationLegError struct {
	// Leg is the leg the finding is about ("leg-<n>"), or "" for the suite.
	Leg string

	// Reason says what is wrong and what fixes it.
	Reason string
}

func (e *IntegrationLegError) Error() string {
	if e.Leg == "" {
		return "integration legs: " + e.Reason
	}
	return "integration legs: " + e.Leg + ": " + e.Reason
}

// integrationLegFindings checks the runner's `legs` listing against the ci.yml
// matrix. The listing's first line is `all <target>...`, every later line
// `leg-<n> <target>...`, n counting up from 1. Every `all` target must be in
// exactly one leg, every leg target in `all`, and the matrix must be 1..N.
func integrationLegFindings(listing string, matrix []int) []*IntegrationLegError {
	lines := strings.Split(strings.TrimSpace(listing), "\n")
	allFields := strings.Fields(lines[0])
	if len(allFields) == 0 || allFields[0] != "all" {
		return []*IntegrationLegError{{Reason: fmt.Sprintf("the listing does not start with the `all` line: %q", lines[0])}}
	}

	var findings []*IntegrationLegError
	legOf := map[string]string{}
	for _, target := range allFields[1:] {
		legOf[target] = ""
	}

	legs := lines[1:]
	for i, line := range legs {
		fields := strings.Fields(line)
		want := fmt.Sprintf("leg-%d", i+1)
		if len(fields) == 0 || fields[0] != want {
			findings = append(findings, &IntegrationLegError{Leg: want, Reason: fmt.Sprintf("line %q is not %s; the legs count up from 1", line, want)})
			continue
		}
		if len(fields) == 1 {
			findings = append(findings, &IntegrationLegError{Leg: want, Reason: "holds no target; drop it from INTEGRATION_LEGS and the ci.yml matrix"})
		}
		for _, target := range fields[1:] {
			owner, known := legOf[target]
			switch {
			case !known:
				findings = append(findings, &IntegrationLegError{Leg: want, Reason: fmt.Sprintf("holds %s, which ALL_TARGETS does not list", target)})
			case owner != "":
				findings = append(findings, &IntegrationLegError{Leg: want, Reason: fmt.Sprintf("holds %s, which %s holds already", target, owner)})
			default:
				legOf[target] = want
			}
		}
	}

	for _, target := range allFields[1:] {
		if legOf[target] == "" {
			findings = append(findings, &IntegrationLegError{Reason: fmt.Sprintf("%s is in no leg; add it to one in INTEGRATION_LEGS", target)})
		}
	}

	if len(matrix) != len(legs) {
		findings = append(findings, &IntegrationLegError{Reason: fmt.Sprintf("the ci.yml matrix runs %d legs, the runner has %d", len(matrix), len(legs))})
		return findings
	}
	for i, leg := range matrix {
		if leg != i+1 {
			findings = append(findings, &IntegrationLegError{Reason: fmt.Sprintf("ci.yml matrix entry %d is %d, want %d", i+1, leg, i+1)})
		}
	}
	return findings
}

// integrationLegMatrix reads the integration job's matrix legs from ci.yml.
func integrationLegMatrix(t *testing.T, root string) []int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, ciWorkflowFile))
	require.NoError(t, err)
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Leg []int `yaml:"leg"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &wf))
	job, ok := wf.Jobs[integrationJobID]
	require.True(t, ok, "%s has no %s job", ciWorkflowFile, integrationJobID)
	return job.Strategy.Matrix.Leg
}

// runIntegrationRunner runs the suite runner with args. Only the arguments
// that exit before anything starts (`legs`, an unknown leg) are safe here.
func runIntegrationRunner(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), bash, append([]string{filepath.Join(repoRoot(t), integrationRunnerPath)}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestIntegrationLegsSplitAllTargetsAndMatchTheCIMatrix(t *testing.T) {
	listing, err := runIntegrationRunner(t, "legs")
	require.NoError(t, err, listing)
	for _, finding := range integrationLegFindings(listing, integrationLegMatrix(t, repoRoot(t))) {
		t.Error(finding)
	}
}

func TestIntegrationRunnerRejectsAnUnknownLeg(t *testing.T) {
	out, err := runIntegrationRunner(t, "leg-99")
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "leg-99 must fail before anything starts: %v\n%s", err, out)
	require.Equal(t, 2, exitErr.ExitCode())
	require.Contains(t, out, "no integration leg 99")
}

func TestIntegrationLegFindingsAcceptAPartition(t *testing.T) {
	listing := "all a b c compute\nleg-1 a c\nleg-2 b compute\n"
	require.Empty(t, integrationLegFindings(listing, []int{1, 2}))
}

func TestIntegrationLegFindingsRejectEachInconsistency(t *testing.T) {
	tests := []struct {
		name    string
		listing string
		matrix  []int
		want    string
	}{
		{"target in no leg", "all a b\nleg-1 a\n", []int{1}, "b is in no leg"},
		{"target in two legs", "all a b\nleg-1 a b\nleg-2 b\n", []int{1, 2}, "holds b, which leg-1 holds already"},
		{"target outside all", "all a\nleg-1 a z\n", []int{1}, "holds z, which ALL_TARGETS does not list"},
		{"empty leg", "all a\nleg-1 a\nleg-2\n", []int{1, 2}, "holds no target"},
		{"misnumbered leg", "all a b\nleg-1 a\nleg-3 b\n", []int{1, 2}, "is not leg-2"},
		{"matrix short", "all a b\nleg-1 a\nleg-2 b\n", []int{1}, "runs 1 legs, the runner has 2"},
		{"matrix misnumbered", "all a b\nleg-1 a\nleg-2 b\n", []int{2, 1}, "matrix entry 1 is 2"},
		{"no all line", "leg-1 a\n", []int{1}, "does not start with the `all` line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := integrationLegFindings(tt.listing, tt.matrix)
			require.NotEmpty(t, findings)
			var reasons []string
			for _, f := range findings {
				reasons = append(reasons, f.Error())
			}
			require.Contains(t, strings.Join(reasons, "\n"), tt.want)
		})
	}
}
