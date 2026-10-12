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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ci.yml runs in two tiers (#852). The PR tier runs on every pull_request; the
// full tier runs on push to main, on workflow_dispatch, and on a PR labelled
// `ci:full`. CI Gate is the one required check, so it alone decides whether a
// skipped job is the tier working or a job that silently never ran. These
// tests hold the three places a tier is written down — the job's `if:`, the
// gate's `needs`, and the gate's tagged `check` line — to one another.
// FIPS is the one main-only job (#853): it never runs on a pull_request and
// must appear in neither the gate's `needs` nor its `check` lines.

const (
	ciWorkflowFile = ".github/workflows/ci.yml"
	ciGateJobID    = "ci-gate"
	ciGateIf       = "always()"

	tierPR   = "pr"
	tierFull = "full"

	// tierMain is the full tier's main-only, ungated part (#853): FIPS, which
	// runs on push to main and on workflow_dispatch, never on a pull_request,
	// and reports without feeding CI Gate because it is still known-red.
	tierMain = "main"

	// fullTierIf is the condition every full-tier job carries as its own `if:`,
	// character for character.
	fullTierIf = "github.event_name == 'push' || github.event_name == 'workflow_dispatch' || contains(github.event.pull_request.labels.*.name, 'ci:full')"

	// mainOnlyIf is fullTierIf without the `ci:full` clause, so no
	// pull_request can select the job.
	mainOnlyIf = "github.event_name == 'push' || github.event_name == 'workflow_dispatch'"

	// fullTierEnv is the gate's rendering of fullTierIf: the gate lets a
	// full-tier job's skip through only when it reads exactly `false`.
	fullTierEnv      = "FULL_TIER"
	fullTierEnvValue = "${{ " + fullTierIf + " }}"

	// supersededGroup keys a run by workflow AND ref, so a push to a PR cancels
	// only that PR's older run (#510).
	supersededGroup = "${{ github.workflow }}-${{ github.ref }}"
)

// prTriggerTypes are ci.yml's pull_request activity types. `ci:full` takes
// effect on the PR's next push or update-branch: there is no `labeled`, see
// labelTypes.
var prTriggerTypes = []string{"opened", "synchronize", "reopened"}

// labelTypes are the pull_request activity types a label change matches. Gitea
// 1.27.1 sends every label add AND remove as `label_updated`, which its
// matcher (modules/actions/workflows.go, matchPullRequestEvent) maps to
// `labeled` without looking at which label moved. A workflow that cancels
// superseded runs and triggers on one restarts the PR's whole run on every
// label change (#853), and a run whose jobs an `if:` skips posts `skipped`
// over the real run's contexts, the required CI Gate among them.
var labelTypes = []string{"labeled", "unlabeled"}

// tierByIf maps a job's `if:` to its tier. A PR-tier job has no `if:`; any
// other condition belongs to no tier and is a finding.
var tierByIf = map[string]string{
	"":         tierPR,
	fullTierIf: tierFull,
	mainOnlyIf: tierMain,
}

var (
	// gateCheckLineRe matches any `check` invocation in the gate's script, so
	// an untagged or malformed one is reported rather than overlooked.
	gateCheckLineRe = regexp.MustCompile(`^\s*check\s`)

	// gateCheckRe captures a well-formed `check <tier> <job> "$RESULT_X"`.
	gateCheckRe = regexp.MustCompile(`^\s*check\s+(\S+)\s+(\S+)\s+"\$(\w+)"\s*$`)
)

// CITierError reports one way ci.yml's tiers, jobs and gate disagree.
type CITierError struct {
	// File is the repo-relative workflow file.
	File string

	// Line is the 1-based line in File, or 0 when unknown.
	Line int

	// Job is the job id (or workflow key) the finding is about.
	Job string

	// Reason says what is wrong and what fixes it.
	Reason string
}

// Error renders the finding as a clickable file:line reference.
func (e CITierError) Error() string {
	return fmt.Sprintf("%s:%d: %s: %s", e.File, e.Line, e.Job, e.Reason)
}

// ciStep is one workflow step, reduced to what the tier check reads.
type ciStep struct {
	Env map[string]string
	Run string

	// RunLine is the 1-based file line of the script's first line.
	RunLine int
}

// ciJob is one workflow job, reduced to what the tier check reads.
type ciJob struct {
	ID    string
	Line  int
	If    string
	Needs []string
	Steps []ciStep
}

// ciGateCheck is one tagged `check` line in the gate's script.
type ciGateCheck struct {
	Tier   string
	Job    string
	EnvVar string
	Line   int
}

// ciWorkflow is a parsed workflow file.
type ciWorkflow struct {
	File string

	// Doc is the top-level mapping, for checks that read beyond the jobs.
	Doc *yaml.Node

	PRTypes     []string
	PRTypesLine int

	// Jobs are in file order.
	Jobs []ciJob
}

// mappingValue returns the value under key in a YAML mapping, or nil when the
// node is nil, is not a mapping, or has no such key.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// parseCIWorkflow parses a workflow file's bytes. It reads the YAML node tree
// rather than a struct so findings can carry line numbers, and so `on:` is
// read as the key it is rather than a YAML 1.1 boolean.
func parseCIWorkflow(file string, data []byte) (ciWorkflow, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return ciWorkflow{}, TestReachLoadError{File: file, Detail: "workflow is not valid YAML", Err: err}
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return ciWorkflow{}, TestReachLoadError{File: file, Detail: "workflow is not a YAML mapping"}
	}
	wf := ciWorkflow{File: file, Doc: root.Content[0]}

	types := mappingValue(mappingValue(mappingValue(wf.Doc, "on"), "pull_request"), "types")
	if types != nil {
		wf.PRTypesLine = types.Line
		if err := types.Decode(&wf.PRTypes); err != nil {
			return ciWorkflow{}, TestReachLoadError{File: file, Line: types.Line, Detail: "on.pull_request.types is not a list", Err: err}
		}
	}

	jobs := mappingValue(wf.Doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return ciWorkflow{}, TestReachLoadError{File: file, Detail: "workflow has no jobs mapping"}
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job, err := parseCIJob(file, jobs.Content[i], jobs.Content[i+1])
		if err != nil {
			return ciWorkflow{}, err
		}
		wf.Jobs = append(wf.Jobs, job)
	}
	return wf, nil
}

// parseCIJob decodes one job from its key and value nodes.
func parseCIJob(file string, key, value *yaml.Node) (ciJob, error) {
	var raw struct {
		If    string    `yaml:"if"`
		Needs yaml.Node `yaml:"needs"`
		Steps []struct {
			Env map[string]string `yaml:"env"`
			Run yaml.Node         `yaml:"run"`
		} `yaml:"steps"`
	}
	if err := value.Decode(&raw); err != nil {
		return ciJob{}, TestReachLoadError{File: file, Line: key.Line, Detail: "job " + key.Value + " does not decode", Err: err}
	}

	job := ciJob{ID: key.Value, Line: key.Line, If: raw.If}
	if raw.Needs.Kind == yaml.ScalarNode {
		job.Needs = []string{raw.Needs.Value}
	} else if raw.Needs.Kind != 0 {
		if err := raw.Needs.Decode(&job.Needs); err != nil {
			return ciJob{}, TestReachLoadError{File: file, Line: raw.Needs.Line, Detail: "job " + key.Value + ": needs is not a job id or a list", Err: err}
		}
	}

	for _, s := range raw.Steps {
		step := ciStep{Env: s.Env, Run: s.Run.Value, RunLine: s.Run.Line}
		// A block scalar's node sits on the `|` line; its text starts below.
		if s.Run.Style == yaml.LiteralStyle || s.Run.Style == yaml.FoldedStyle {
			step.RunLine++
		}
		job.Steps = append(job.Steps, step)
	}
	return job, nil
}

// loadCIWorkflow reads and parses a workflow file, failing the test on error.
func loadCIWorkflow(t *testing.T, root, rel string) ciWorkflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	require.NoError(t, err)
	wf, err := parseCIWorkflow(rel, data)
	require.NoError(t, err)
	return wf
}

// gateCheckStep returns the gate step whose script carries the check lines.
func gateCheckStep(gate ciJob) (ciStep, bool) {
	for _, step := range gate.Steps {
		for _, line := range strings.Split(step.Run, "\n") {
			if gateCheckLineRe.MatchString(line) {
				return step, true
			}
		}
	}
	return ciStep{}, false
}

// parseGateChecks extracts the tagged check lines from the gate's script, and
// reports every `check` line that is not in the tagged form.
func parseGateChecks(file string, step ciStep) ([]ciGateCheck, []error) {
	var checks []ciGateCheck
	var findings []error
	for i, line := range strings.Split(step.Run, "\n") {
		if !gateCheckLineRe.MatchString(line) {
			continue
		}
		lineNo := step.RunLine + i
		m := gateCheckRe.FindStringSubmatch(line)
		if m == nil {
			findings = append(findings, CITierError{
				File: file, Line: lineNo, Job: ciGateJobID,
				Reason: "check line is not `check <pr|full> <job> \"$RESULT_X\"`: " + strings.TrimSpace(line),
			})
			continue
		}
		checks = append(checks, ciGateCheck{Tier: m[1], Job: m[2], EnvVar: m[3], Line: lineNo})
	}
	return checks, findings
}

// checkLineFindings validates one tagged check line against the jobs and the
// gate step's env. seen holds the check lines already validated.
func checkLineFindings(file string, c ciGateCheck, jobs map[string]ciJob, env map[string]string, seen map[string]ciGateCheck) []error {
	var findings []error
	fail := func(reason string) {
		findings = append(findings, CITierError{File: file, Line: c.Line, Job: c.Job, Reason: reason})
	}
	if c.Tier != tierPR && c.Tier != tierFull {
		fail(fmt.Sprintf("tier tag %q is neither %q nor %q", c.Tier, tierPR, tierFull))
	}
	if _, ok := jobs[c.Job]; !ok || c.Job == ciGateJobID {
		fail("ci-gate checks a job the workflow does not define")
	}
	if prev, dup := seen[c.Job]; dup {
		fail(fmt.Sprintf("checked twice; the first check is at line %d", prev.Line))
	}
	want := "${{ needs." + c.Job + ".result }}"
	if got := env[c.EnvVar]; got != want {
		fail(fmt.Sprintf("$%s is %q in the gate's env, want %q", c.EnvVar, got, want))
	}
	return findings
}

// gateFindings validates the gate job itself and returns its check lines,
// keyed by job id.
func gateFindings(wf ciWorkflow, gate ciJob, jobs map[string]ciJob) (map[string]ciGateCheck, []error) {
	var findings []error
	fail := func(line int, reason string) {
		findings = append(findings, CITierError{File: wf.File, Line: line, Job: ciGateJobID, Reason: reason})
	}
	if gate.If != ciGateIf {
		fail(gate.Line, fmt.Sprintf("if: is %q, want %q: without it a failed job skips the gate instead of failing it", gate.If, ciGateIf))
	}
	for _, need := range gate.Needs {
		if _, ok := jobs[need]; !ok {
			fail(gate.Line, "needs "+need+", which the workflow does not define")
		}
	}

	step, ok := gateCheckStep(gate)
	if !ok {
		fail(gate.Line, "the gate has no check lines")
		return nil, findings
	}
	if got := step.Env[fullTierEnv]; got != fullTierEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q, the full-tier jobs' `if:`", fullTierEnv, got, fullTierEnvValue))
	}

	checks, parseErrs := parseGateChecks(wf.File, step)
	findings = append(findings, parseErrs...)
	checked := make(map[string]ciGateCheck, len(checks))
	for _, c := range checks {
		findings = append(findings, checkLineFindings(wf.File, c, jobs, step.Env, checked)...)
		if _, dup := checked[c.Job]; !dup {
			checked[c.Job] = c
		}
	}
	return checked, findings
}

// ciTierFindings reports every way ci.yml's triggers, job tiers and gate
// disagree. An empty result means every job is gated, tagged with the tier its
// `if:` gives it, and no PR-tier job waits on a full-tier one.
func ciTierFindings(wf ciWorkflow) []error {
	var findings []error
	if !slices.Equal(wf.PRTypes, prTriggerTypes) {
		findings = append(findings, CITierError{
			File: wf.File, Line: wf.PRTypesLine, Job: "on.pull_request",
			Reason: fmt.Sprintf("types are %v, want %v: ci:full takes effect on the next push, not on a label event", wf.PRTypes, prTriggerTypes),
		})
	}

	jobs := make(map[string]ciJob, len(wf.Jobs))
	for _, j := range wf.Jobs {
		jobs[j.ID] = j
	}
	gate, ok := jobs[ciGateJobID]
	if !ok {
		return append(findings, CITierError{File: wf.File, Job: ciGateJobID, Reason: "the workflow has no ci-gate job"})
	}
	checked, gateErrs := gateFindings(wf, gate, jobs)
	findings = append(findings, gateErrs...)

	tiers := make(map[string]string, len(wf.Jobs))
	for _, j := range wf.Jobs {
		if j.ID == ciGateJobID {
			continue
		}
		tier, known := tierByIf[j.If]
		if !known {
			findings = append(findings, CITierError{
				File: wf.File, Line: j.Line, Job: j.ID,
				Reason: fmt.Sprintf("if: %q is no tier: a PR-tier job has no `if:`, a full-tier job has exactly %q, a main-only job exactly %q", j.If, fullTierIf, mainOnlyIf),
			})
			continue
		}
		tiers[j.ID] = tier
	}

	for _, j := range wf.Jobs {
		if j.ID == ciGateJobID {
			continue
		}
		fail := func(line int, reason string) {
			findings = append(findings, CITierError{File: wf.File, Line: line, Job: j.ID, Reason: reason})
		}
		tier, known := tiers[j.ID]
		c, gated := checked[j.ID]
		if tier == tierMain {
			if slices.Contains(gate.Needs, j.ID) {
				fail(j.Line, "a main-only job is ungated: remove it from ci-gate's needs")
			}
			if gated {
				fail(c.Line, "a main-only job is ungated: remove its check line from ci-gate")
			}
			continue
		}
		if !slices.Contains(gate.Needs, j.ID) {
			fail(j.Line, "not in ci-gate's needs: the gate cannot see its result")
		}
		if !gated {
			fail(j.Line, "no check line in ci-gate: add `check <tier> "+j.ID+" \"$RESULT_X\"`")
		} else if known && c.Tier != tier {
			fail(c.Line, fmt.Sprintf("tagged %s in ci-gate, but its if: puts it in the %s tier", c.Tier, tier))
		}
		for _, need := range j.Needs {
			if tiers[need] == tierMain {
				fail(j.Line, "a gated job needs main-only job "+need+": skipped on every PR, it would skip this job too")
			}
			if tier == tierPR && tiers[need] == tierFull {
				fail(j.Line, "a PR-tier job needs full-tier job "+need+": skipped on every ordinary PR, it would skip this job too")
			}
		}
	}
	return findings
}

// workflowTriggers lists the events a workflow's `on:` names, in any of its
// three forms (a scalar, a list, or a mapping).
func workflowTriggers(doc *yaml.Node) []string {
	on := mappingValue(doc, "on")
	if on == nil {
		return nil
	}
	if on.Kind == yaml.ScalarNode {
		return []string{on.Value}
	}
	var events []string
	step := 1
	if on.Kind == yaml.MappingNode {
		step = 2
	}
	for i := 0; i < len(on.Content); i += step {
		events = append(events, on.Content[i].Value)
	}
	return events
}

// concurrencyFindings reports a pull_request-triggered workflow that does not
// cancel its superseded runs. pull_request_target is deliberately not held to
// this: its github.ref is the BASE branch, so a ref-keyed group would put every
// PR in one group and let each cancel the others; those workflows key by PR.
func concurrencyFindings(wf ciWorkflow) []error {
	if !slices.Contains(workflowTriggers(wf.Doc), "pull_request") {
		return nil
	}
	fail := func(line int, reason string) []error {
		return []error{CITierError{File: wf.File, Line: line, Job: "concurrency", Reason: reason}}
	}
	block := mappingValue(wf.Doc, "concurrency")
	if block == nil {
		return fail(0, "triggered by pull_request but has no concurrency block")
	}
	var findings []error
	if group := mappingValue(block, "group"); group == nil || group.Value != supersededGroup {
		findings = append(findings, fail(block.Line, "group must be "+supersededGroup+", one group per workflow and ref")...)
	}
	cancel := mappingValue(block, "cancel-in-progress")
	if cancel == nil || cancel.ShortTag() != "!!bool" || cancel.Value != "true" {
		findings = append(findings, fail(block.Line, "cancel-in-progress must be the literal true: Gitea 1.27.1 does not evaluate an expression there")...)
	}
	for _, label := range labelTypes {
		if slices.Contains(wf.PRTypes, label) {
			findings = append(findings, CITierError{File: wf.File, Line: wf.PRTypesLine, Job: "on.pull_request",
				Reason: "types include " + label + ": Gitea 1.27.1 reports every label add and remove as labeled, so each label change cancels and restarts the PR's run"})
		}
	}
	return findings
}

// TestCIGateTiersMatchTheJobs is the ratchet on the real ci.yml.
func TestCIGateTiersMatchTheJobs(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	for _, finding := range ciTierFindings(wf) {
		t.Error(finding)
	}
}

// TestPullRequestWorkflowsCancelSupersededRuns holds every workflow a
// pull_request triggers to the ref-keyed, cancelling concurrency block.
func TestPullRequestWorkflowsCancelSupersededRuns(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, workflowsDir, "*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	sawPullRequest := false
	for _, path := range files {
		rel, relErr := filepath.Rel(root, path)
		require.NoError(t, relErr)
		wf := loadCIWorkflow(t, root, rel)
		if slices.Contains(workflowTriggers(wf.Doc), "pull_request") {
			sawPullRequest = true
		}
		for _, finding := range concurrencyFindings(wf) {
			t.Error(finding)
		}
	}
	require.True(t, sawPullRequest, "no workflow is triggered by pull_request; the check measured nothing")
}

// TestCIGateScriptPassesASkipOnlyForAnUnselectedFullTier runs the real gate
// script under bash with the results a runner would hand it.
func TestCIGateScriptPassesASkipOnlyForAnUnselectedFullTier(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	gateIdx := slices.IndexFunc(wf.Jobs, func(j ciJob) bool { return j.ID == ciGateJobID })
	require.GreaterOrEqual(t, gateIdx, 0, "ci.yml has no ci-gate job")
	step, ok := gateCheckStep(wf.Jobs[gateIdx])
	require.True(t, ok, "ci-gate has no check lines")
	checks, findings := parseGateChecks(wf.File, step)
	require.Empty(t, findings)

	prIdx := slices.IndexFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierPR })
	fullIdx := slices.IndexFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierFull })
	require.GreaterOrEqual(t, prIdx, 0, "the gate checks no pr-tier job")
	require.GreaterOrEqual(t, fullIdx, 0, "the gate checks no full-tier job")
	prVar, fullVar := checks[prIdx].EnvVar, checks[fullIdx].EnvVar

	everyFullSkipped := make(map[string]string)
	for _, c := range checks {
		if c.Tier == tierFull {
			everyFullSkipped[c.EnvVar] = "skipped"
		}
	}

	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	cases := []struct {
		name     string
		fullTier string
		results  map[string]string
		wantPass bool
	}{
		{"every job succeeded on a full-tier run", "true", nil, true},
		{"the full tier skipped on an ordinary PR", "false", everyFullSkipped, true},
		{"a full-tier job skipped although the full tier was selected", "true", map[string]string{fullVar: "skipped"}, false},
		{"a full-tier job skipped while FULL_TIER did not render", "", map[string]string{fullVar: "skipped"}, false},
		{"a pr-tier job skipped", "false", map[string]string{prVar: "skipped"}, false},
		{"a full-tier job failed on an ordinary PR", "false", map[string]string{fullVar: "failure"}, false},
		{"a result that did not render", "false", map[string]string{prVar: ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"PATH=" + os.Getenv("PATH"), fullTierEnv + "=" + tc.fullTier}
			for _, c := range checks {
				result, set := tc.results[c.EnvVar]
				if !set {
					result = "success"
				}
				env = append(env, c.EnvVar+"="+result)
			}
			// -eo pipefail is the runner's default bash invocation for `run:`.
			cmd := exec.CommandContext(t.Context(), bash, "-eo", "pipefail", "-c", step.Run)
			cmd.Env = env
			out, runErr := cmd.CombinedOutput()
			if tc.wantPass {
				require.NoError(t, runErr, string(out))
				return
			}
			var exitErr *exec.ExitError
			require.ErrorAs(t, runErr, &exitErr, "the gate passed:\n%s", out)
		})
	}
}

// fixtureTieredCI is a minimal consistent tiered workflow the negative cases
// below each break in one place.
const fixtureTieredCI = `on:
  pull_request:
    types: [opened, synchronize, reopened]
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  lint:
    runs-on: x
  race:
    if: ` + fullTierIf + `
    needs: lint
  fips:
    if: ` + mainOnlyIf + `
  ci-gate:
    if: always()
    needs: [lint, race]
    steps:
      - env:
          FULL_TIER: ` + fullTierEnvValue + `
          RESULT_LINT: ${{ needs.lint.result }}
          RESULT_RACE: ${{ needs.race.result }}
        run: |
          check pr lint "$RESULT_LINT"
          check full race "$RESULT_RACE"
`

func parseFixture(t *testing.T, data string) ciWorkflow {
	t.Helper()
	wf, err := parseCIWorkflow("ci.yml", []byte(data))
	require.NoError(t, err)
	return wf
}

func TestCITierFindingsAcceptAConsistentWorkflow(t *testing.T) {
	wf := parseFixture(t, fixtureTieredCI)
	require.Empty(t, ciTierFindings(wf))
	require.Empty(t, concurrencyFindings(wf))
}

func TestCITierFindingsRejectEachInconsistency(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"a full-tier job tagged pr", `check full race`, `check pr race`, "race: tagged pr in ci-gate, but its if: puts it in the full tier"},
		{"a pr-tier job tagged full", `check pr lint`, `check full lint`, "lint: tagged full in ci-gate, but its if: puts it in the pr tier"},
		{"an untagged check line", `check pr lint "$RESULT_LINT"`, `check lint "$RESULT_LINT"`, "check line is not"},
		{"an unknown tier tag", `check pr lint`, `check fast lint`, `tier tag "fast" is neither`},
		{"a job with no check line", "          check pr lint \"$RESULT_LINT\"\n", "", "lint: no check line in ci-gate"},
		{"a job missing from the gate's needs", `needs: [lint, race]`, `needs: [lint]`, "race: not in ci-gate's needs"},
		{"a full-tier if: that drifted", "'ci:full')\n    needs: lint", "'ci-full')\n    needs: lint", "race: if: "},
		{"a pr-tier job needing a full-tier job", "  lint:\n    runs-on: x\n", "  lint:\n    runs-on: x\n    needs: race\n", "a PR-tier job needs full-tier job race"},
		{"a check reading another job's result", `RESULT_RACE: ${{ needs.race.result }}`, `RESULT_RACE: ${{ needs.lint.result }}`, "$RESULT_RACE is"},
		{"a FULL_TIER that drifted from the jobs' if:", `FULL_TIER: ${{ github.event_name == 'push'`, `FULL_TIER: ${{ github.event_name == 'pull_request'`, "$FULL_TIER is"},
		{"a gate that does not always run", `if: always()`, `if: success()`, `if: is "success()"`},
		{"a gate checking an undefined job", `check full race "$RESULT_RACE"`, "check full race \"$RESULT_RACE\"\n          check pr ghost \"$RESULT_RACE\"", "ghost: ci-gate checks a job the workflow does not define"},
		{"pull_request with the labeled type", `reopened]`, `reopened, labeled]`, "not on a label event"},
		{"pull_request without the synchronize type", `synchronize, `, ``, "types are [opened reopened]"},
		{"a main-only job in the gate's needs", `needs: [lint, race]`, `needs: [lint, race, fips]`, "fips: a main-only job is ungated: remove it from ci-gate's needs"},
		{"a main-only job with a check line", `check full race "$RESULT_RACE"`, "check full race \"$RESULT_RACE\"\n          check full fips \"$RESULT_RACE\"", "fips: a main-only job is ungated: remove its check line"},
		{"a main-only job a ci:full PR can select", "  fips:\n    if: " + mainOnlyIf + "\n", "  fips:\n    if: " + fullTierIf + "\n", "fips: not in ci-gate's needs"},
		{"a main-only job without workflow_dispatch", "  fips:\n    if: " + mainOnlyIf + "\n", "  fips:\n    if: github.event_name == 'push'\n", "fips: if: "},
		{"a gated job needing a main-only job", "    needs: lint\n  fips:", "    needs: [lint, fips]\n  fips:", "race: a gated job needs main-only job fips"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(fixtureTieredCI, tc.old, tc.new, 1)
			require.NotEqual(t, fixtureTieredCI, mutated, "the mutation did not apply")

			var rendered []string
			for _, finding := range ciTierFindings(parseFixture(t, mutated)) {
				var tierErr CITierError
				require.ErrorAs(t, finding, &tierErr)
				rendered = append(rendered, finding.Error())
			}
			require.NotEmpty(t, rendered)
			require.True(t, slices.ContainsFunc(rendered, func(s string) bool { return strings.Contains(s, tc.want) }),
				"no finding contains %q:\n%s", tc.want, strings.Join(rendered, "\n"))
		})
	}
}

func TestCITierFindingsPointAtTheMisTaggedLine(t *testing.T) {
	mutated := strings.Replace(fixtureTieredCI, `check full race`, `check pr race`, 1)
	findings := ciTierFindings(parseFixture(t, mutated))
	require.Len(t, findings, 1)
	var tierErr CITierError
	require.ErrorAs(t, findings[0], &tierErr)
	// The fixture's last line is the race check.
	require.Equal(t, strings.Count(fixtureTieredCI, "\n"), tierErr.Line)
}

func TestConcurrencyFindingsRejectAnUncancellableGroup(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"an expression for cancel-in-progress", `cancel-in-progress: true`, `cancel-in-progress: ${{ true }}`, "must be the literal true"},
		{"cancel-in-progress false", `cancel-in-progress: true`, `cancel-in-progress: false`, "must be the literal true"},
		{"a group with no ref", `group: ${{ github.workflow }}-${{ github.ref }}`, `group: ${{ github.workflow }}`, "group must be"},
		{"no concurrency block", "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n", "", "has no concurrency block"},
		{"a labeled trigger", `reopened]`, `reopened, labeled]`, "types include labeled"},
		{"an unlabeled trigger", `reopened]`, `reopened, unlabeled]`, "types include unlabeled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(fixtureTieredCI, tc.old, tc.new, 1)
			require.NotEqual(t, fixtureTieredCI, mutated, "the mutation did not apply")
			findings := concurrencyFindings(parseFixture(t, mutated))
			require.Len(t, findings, 1)
			require.Contains(t, findings[0].Error(), tc.want)
		})
	}
}

func TestConcurrencyFindingsIgnoreWorkflowsWithoutAPullRequestTrigger(t *testing.T) {
	for _, on := range []string{"on: workflow_dispatch", "on: [push, workflow_dispatch]", "on:\n  pull_request_target:\n    types: [opened]"} {
		wf := parseFixture(t, on+"\njobs:\n  a:\n    runs-on: x\n")
		require.Empty(t, concurrencyFindings(wf), on)
	}
}

func TestParseCIWorkflowRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"not YAML", "jobs: [unclosed", "not valid YAML"},
		{"empty", "", "not a YAML mapping"},
		{"a list", "- a\n- b\n", "not a YAML mapping"},
		{"no jobs", "on: push\n", "no jobs mapping"},
		{"needs not a list", "jobs:\n  a:\n    needs: {x: y}\n", "needs is not a job id or a list"},
		{"types not a list", "on:\n  pull_request:\n    types: {a: b}\njobs:\n  a: {}\n", "on.pull_request.types is not a list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCIWorkflow("ci.yml", []byte(tc.data))
			var loadErr TestReachLoadError
			require.ErrorAs(t, err, &loadErr)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}
