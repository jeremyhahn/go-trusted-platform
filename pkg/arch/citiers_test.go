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
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ci.yml runs in two tiers (#852, ci-template v1.23). The PR tier runs on
// every pull_request; the full tier runs on push to main, on
// workflow_dispatch, and on a PR labelled `ci:full`. CI Gate is the one
// required check, so it alone decides whether a skipped job is the tier
// working or a job that silently never ran. These tests hold the three places
// a tier is written down — the job's `if:`, the gate's `needs`, and the gate's
// tagged `check` line — to one another. The docs tier (ci-template v1.24) is
// the PR-tier work a docs-only PR skips: those jobs need the `changes` job and
// skip when its docs_only output is `true`. A draft PR runs no CI
// (ci-template v1.26): every job's `if:` carries the draft guard, and the gate
// fails on a draft. The nightly tier (ci-template v1.27, ruling 135) runs on
// main's schedule and on a dispatch: its soak may skip only when the gate's
// NIGHTLY flag is not `true`. The main tier (#1411, ruling 297) runs on main,
// the schedule and dispatch, never on a pull request (DS-4613): FIPS is gated
// there, and its skip passes only when the gate's PULL_REQUEST flag is `true`.

const (
	ciWorkflowFile = ".github/workflows/ci.yml"
	ciGateJobID    = "ci-gate"
	// ciGateIf runs the gate after every job, failed or skipped, except on a
	// schedule run the schedule guard found busy (v1.29.3): that run posts
	// `skipped`, never a green nightly.
	ciGateIf = "${{ always() && (github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict != 'busy') }}"

	// scheduleGuardJobID is the job that, on a schedule run, reads whether a
	// main push run is in flight and sets `verdict` (v1.29.3, ruling
	// 255(10)/(11)(c)).
	scheduleGuardJobID = "schedule-guard"

	// bigdiskLabel is the runner label of the jobs the schedule guard holds.
	bigdiskLabel = "bigdisk"

	// scheduleGuardExpr is the clause every bigdisk job's `if:` carries: off
	// schedule it is true, on a schedule run only on the guard's `run`.
	scheduleGuardExpr = "github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict == 'run'"

	// prTierGuardedIf, docsOnlyGuardedIf, fullTierGuardedIf and
	// nightlyGuardedIf are the tier `if:`s of a bigdisk job, character for
	// character: the tier's own condition and the schedule guard.
	// docsOnlyGuardedIf (2026-11-10, m2406): race on the bigdisk runner.
	prTierGuardedIf   = "${{ " + draftGuard + " && (" + scheduleGuardExpr + ") }}"
	docsOnlyGuardedIf = "${{ needs.changes.outputs.docs_only != 'true' && " + draftGuard + " && (" + scheduleGuardExpr + ") }}"
	fullTierGuardedIf = "${{ (" + fullTierExpr + ") && " + draftGuard + " && (" + scheduleGuardExpr + ") }}"
	nightlyGuardedIf  = "${{ (github.event_name == 'schedule' && needs.schedule-guard.outputs.verdict == 'run') || github.event_name == 'workflow_dispatch' }}"

	// scheduleEnv and scheduleGuardEnv are the gate's schedule flag and the
	// guard's verdict: on a schedule run the gate fails on any verdict but
	// `run`.
	scheduleEnv           = "SCHEDULE"
	scheduleEnvValue      = "${{ github.event_name == 'schedule' }}"
	scheduleGuardEnv      = "SCHEDULE_GUARD"
	scheduleGuardEnvValue = "${{ needs.schedule-guard.outputs.verdict }}"

	tierPR   = "pr"
	tierDocs = "docs"
	tierFull = "full"

	// tierNightly is the scheduled tier (ci-template v1.27, ruling 135): the
	// soak runs on main's schedule and on a dispatch, never on a PR or a push.
	tierNightly = "nightly"

	// nightlyExpr selects the nightly tier. A PR event never matches it, so
	// the draft guard is not repeated in nightlyIf.
	nightlyExpr = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"

	// nightlyIf is the `if:` of every nightly-tier job, character for character.
	nightlyIf = "${{ " + nightlyExpr + " }}"

	// nightlyEnv is the gate's nightly flag: the gate lets a nightly-tier
	// job's skip through only when it reads anything but `true`.
	nightlyEnv      = "NIGHTLY"
	nightlyEnvValue = nightlyIf

	// tierMain is the tier of a job that runs on every event but a pull
	// request: push to main, the schedule and dispatch (#1411, ruling 297).
	// The gate lets its skip through only on a pull request.
	tierMain = "main"

	// pullRequestEnv is the gate's pull-request flag: the gate lets a
	// main-tier job's skip through only when it reads exactly `true`.
	pullRequestEnv      = "PULL_REQUEST"
	pullRequestEnvValue = "${{ github.event_name == 'pull_request' }}"

	// changesJobID is the job whose docs_only output selects the docs tier.
	changesJobID = "changes"

	// draftGuard is in every job's `if:`: a draft PR runs no CI (v1.26).
	draftGuard = "!github.event.pull_request.draft"

	// prTierIf is the `if:` of every PR-tier job: the draft guard alone.
	prTierIf = "${{ " + draftGuard + " }}"

	// docsOnlyIf is the condition every docs-tier job carries as its own
	// `if:`, character for character: it runs unless docs_only is `true`.
	docsOnlyIf = "${{ needs.changes.outputs.docs_only != 'true' && " + draftGuard + " }}"

	// docsOnlyEnv is the gate's rendering of the changes job's output: the
	// gate lets a docs-tier job's skip through only when it reads exactly
	// `true` (and FULL_TIER exactly `false`).
	docsOnlyEnv      = "DOCS_ONLY"
	docsOnlyEnvValue = "${{ needs.changes.outputs.docs_only }}"

	// fullTierExpr selects the full tier: every event but pull_request, and a
	// PR labelled ci:full. The workflow's CI_FULL_TIER env is this
	// expression; a job-level `if:` cannot read env, so each full-tier job
	// repeats it in fullTierIf.
	fullTierExpr = "github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full')"

	// fullTierIf is the condition every full-tier job carries as its own `if:`,
	// character for character.
	fullTierIf = "${{ (" + fullTierExpr + ") && " + draftGuard + " }}"

	// mainOnlyIf is the `if:` of every main-tier job: push to main, the
	// schedule and workflow_dispatch, never a pull request, `ci:full` or not
	// (m1355 / DS-3878, DS-4613; gated since #1411, ruling 297).
	mainOnlyIf = "${{ github.event_name != 'pull_request' }}"

	// ciFullTierEnv is the workflow-level env the steps and the gate read.
	ciFullTierEnv      = "CI_FULL_TIER"
	ciFullTierEnvValue = "${{ " + fullTierExpr + " }}"

	// fullTierEnv is the gate's rendering of CI_FULL_TIER: the gate lets a
	// full-tier job's skip through only when it reads exactly `false`.
	fullTierEnv      = "FULL_TIER"
	fullTierEnvValue = "${{ env." + ciFullTierEnv + " }}"

	// draftEnv is the gate's draft flag: the gate fails when it reads `true`.
	draftEnv      = "DRAFT"
	draftEnvValue = "${{ github.event.pull_request.draft == true }}"

	// supersededGroup keys a run by workflow AND ref, so a push to a PR cancels
	// only that PR's older run (#510). On main it keys by event and commit
	// instead (ci-template v1.26.2, ruling 145), so each main run is its own
	// group: the next push to main never cancels the run in progress
	// (DS-3465), and a dispatch never shares a group with a push. A schedule
	// run keys by repository alone, tested first (v1.29.3, ruling
	// 255(10)/(11)(c)), so a repository has one schedule run at a time. Gitea
	// 1.27.1 evaluates expressions in `group`, not in `cancel-in-progress`.
	supersededGroup = "${{ github.workflow }}-${{ github.event_name == 'schedule' && format('schedule-{0}', github.repository) || github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}"
)

// prTriggerTypes are ci.yml's pull_request activity types. `ci:full` takes
// effect on the PR's next push or update-branch: there is no `labeled`, see
// labelTypes. There is no `ready_for_review` or `edited` either: a draft
// marked ready starts its run on the next push.
var prTriggerTypes = []string{"opened", "synchronize", "reopened"}

// labelTypes are the pull_request activity types a label change matches. Gitea
// 1.27.1 sends every label add AND remove as `label_updated`, which its
// matcher (modules/actions/workflows.go, matchPullRequestEvent) maps to
// `labeled` without looking at which label moved. A workflow that cancels
// superseded runs and triggers on one restarts the PR's whole run on every
// label change (#853), and a run whose jobs an `if:` skips posts `skipped`
// over the real run's contexts, the required CI Gate among them.
var labelTypes = []string{"labeled", "unlabeled"}

// tierByIf maps a job's `if:` to its tier. Any other condition, no `if:`
// included, belongs to no tier and is a finding.
var tierByIf = map[string]string{
	prTierIf:   tierPR,
	docsOnlyIf: tierDocs,
	fullTierIf: tierFull,
	nightlyIf:  tierNightly,
	mainOnlyIf: tierMain,

	prTierGuardedIf:   tierPR,
	docsOnlyGuardedIf: tierDocs,
	fullTierGuardedIf: tierFull,
	nightlyGuardedIf:  tierNightly,
}

// scheduleGuardedIf holds the `if:`s that read the schedule guard's verdict.
var scheduleGuardedIf = map[string]bool{
	prTierGuardedIf:   true,
	docsOnlyGuardedIf: true,
	fullTierGuardedIf: true,
	nightlyGuardedIf:  true,
}

// gatedTiers are the tiers a gate `check` line may carry.
var gatedTiers = []string{tierPR, tierDocs, tierFull, tierNightly, tierMain}

// tierLabel names a gated tier in a finding.
var tierLabel = map[string]string{
	tierPR:      "PR",
	tierDocs:    "docs",
	tierFull:    "full",
	tierNightly: "nightly",
	tierMain:    "main",
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
	ID     string
	Line   int
	If     string
	RunsOn string
	Needs  []string
	Steps  []ciStep
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
		If     string    `yaml:"if"`
		RunsOn yaml.Node `yaml:"runs-on"`
		Needs  yaml.Node `yaml:"needs"`
		Steps  []struct {
			Env map[string]string `yaml:"env"`
			Run yaml.Node         `yaml:"run"`
		} `yaml:"steps"`
	}
	if err := value.Decode(&raw); err != nil {
		return ciJob{}, TestReachLoadError{File: file, Line: key.Line, Detail: "job " + key.Value + " does not decode", Err: err}
	}

	job := ciJob{ID: key.Value, Line: key.Line, If: raw.If, RunsOn: raw.RunsOn.Value}
	// A label list: every label, so a bigdisk label in it is seen.
	for _, label := range raw.RunsOn.Content {
		job.RunsOn += " " + label.Value
	}
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
				Reason: "check line is not `check <pr|docs|full> <job> \"$RESULT_X\"`: " + strings.TrimSpace(line),
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
	if !slices.Contains(gatedTiers, c.Tier) {
		fail(fmt.Sprintf("tier tag %q is none of %q", c.Tier, gatedTiers))
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
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q, the workflow's full-tier selection", fullTierEnv, got, fullTierEnvValue))
	}
	if got := step.Env[draftEnv]; got != draftEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: a draft PR's gate must fail, not pass on its skips", draftEnv, got, draftEnvValue))
	}
	if _, ok := jobs[scheduleGuardJobID]; !ok {
		fail(gate.Line, "the workflow has no "+scheduleGuardJobID+" job: a schedule run's bigdisk jobs would run while main is busy")
	}
	if got := step.Env[scheduleEnv]; got != scheduleEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: without it a schedule run passes on bigdisk jobs the guard skipped", scheduleEnv, got, scheduleEnvValue))
	}
	if got := step.Env[scheduleGuardEnv]; got != scheduleGuardEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: without it a schedule run passes on bigdisk jobs the guard skipped", scheduleGuardEnv, got, scheduleGuardEnvValue))
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
	docsTagged := slices.ContainsFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierDocs })
	if got := step.Env[docsOnlyEnv]; docsTagged && got != docsOnlyEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: a docs-tier skip passes only on the changes job's word", docsOnlyEnv, got, docsOnlyEnvValue))
	}
	nightlyTagged := slices.ContainsFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierNightly })
	if got := step.Env[nightlyEnv]; nightlyTagged && got != nightlyEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: without it a nightly run passes on a skipped soak", nightlyEnv, got, nightlyEnvValue))
	}
	mainTagged := slices.ContainsFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierMain })
	if got := step.Env[pullRequestEnv]; mainTagged && got != pullRequestEnvValue {
		fail(step.RunLine, fmt.Sprintf("$%s is %q, want %q: without it a push passes on a skipped main-tier job", pullRequestEnv, got, pullRequestEnvValue))
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

	envNode := mappingValue(mappingValue(wf.Doc, "env"), ciFullTierEnv)
	if envNode == nil || envNode.Value != ciFullTierEnvValue {
		line, got := 0, ""
		if envNode != nil {
			line, got = envNode.Line, envNode.Value
		}
		findings = append(findings, CITierError{
			File: wf.File, Line: line, Job: "env",
			Reason: fmt.Sprintf("%s is %q, want %q, the full-tier jobs' `if:` without the draft guard", ciFullTierEnv, got, ciFullTierEnvValue),
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
	docsTier := false
	for _, j := range wf.Jobs {
		if j.ID == ciGateJobID {
			continue
		}
		tier, known := tierByIf[j.If]
		if !known {
			findings = append(findings, CITierError{
				File: wf.File, Line: j.Line, Job: j.ID,
				Reason: fmt.Sprintf("if: %q is no tier: a PR-tier job has exactly %q, a docs-tier job exactly %q, a full-tier job exactly %q, a nightly-tier job exactly %q, a main-tier job exactly %q", j.If, prTierIf, docsOnlyIf, fullTierIf, nightlyIf, mainOnlyIf),
			})
			continue
		}
		tiers[j.ID] = tier
		docsTier = docsTier || tier == tierDocs
	}
	if _, ok := jobs[changesJobID]; !ok && docsTier {
		findings = append(findings, CITierError{File: wf.File, Job: changesJobID, Reason: "the docs tier has no changes job to read docs_only from"})
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
		guarded := scheduleGuardedIf[j.If]
		if strings.Contains(j.RunsOn, bigdiskLabel) && !guarded {
			fail(j.Line, "a bigdisk job's if: carries the schedule guard `("+scheduleGuardExpr+")`: without it a schedule run fills the runner while main is busy")
		}
		if guarded && !slices.Contains(j.Needs, scheduleGuardJobID) {
			fail(j.Line, "its if: reads the schedule guard, so it needs "+scheduleGuardJobID+": without it the verdict does not render and a schedule run skips the job")
		}
		if !slices.Contains(gate.Needs, j.ID) {
			fail(j.Line, "not in ci-gate's needs: the gate cannot see its result")
		}
		if !gated {
			fail(j.Line, "no check line in ci-gate: add `check <tier> "+j.ID+" \"$RESULT_X\"`")
		} else if known && c.Tier != tier {
			fail(c.Line, fmt.Sprintf("tagged %s in ci-gate, but its if: puts it in the %s tier", c.Tier, tier))
		}
		if tier == tierDocs && !slices.Contains(j.Needs, changesJobID) {
			fail(j.Line, "a docs-tier job needs "+changesJobID+": without it, docs_only does not render and the job always runs")
		}
		for _, need := range j.Needs {
			if tier != tierMain && tiers[need] == tierMain {
				fail(j.Line, "a "+tierLabel[tier]+"-tier job needs main-tier job "+need+": skipped on every PR, it would skip this job too")
			}
			if (tier == tierPR || tier == tierDocs) && tiers[need] == tierFull {
				fail(j.Line, "a "+tierLabel[tier]+"-tier job needs full-tier job "+need+": skipped on every ordinary PR, it would skip this job too")
			}
			if tier == tierPR && tiers[need] == tierDocs {
				fail(j.Line, "a PR-tier job needs docs-tier job "+need+": skipped on every docs-only PR, it would skip this job too")
			}
			if tier != tierNightly && tiers[need] == tierNightly {
				fail(j.Line, "a "+tierLabel[tier]+"-tier job needs nightly-tier job "+need+": skipped on every PR and push, it would skip this job too")
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
// cancel its superseded PR runs, or that lets a push to main cancel the main
// run in progress. pull_request_target is deliberately not held to
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
		findings = append(findings, fail(block.Line, "group must be "+supersededGroup+": one group per workflow and ref, so a PR push supersedes only its own run, and one per commit on main, so no push cancels a main run")...)
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

// TestCIGateScriptPassesASkipOnlyForAnUnselectedTier runs the real gate
// script under bash with the results a runner would hand it.
// loadGateStep returns ci.yml's gate step and its check lines.
func loadGateStep(t *testing.T) (ciStep, []ciGateCheck) {
	t.Helper()
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	gateIdx := slices.IndexFunc(wf.Jobs, func(j ciJob) bool { return j.ID == ciGateJobID })
	require.GreaterOrEqual(t, gateIdx, 0, "ci.yml has no ci-gate job")
	step, ok := gateCheckStep(wf.Jobs[gateIdx])
	require.True(t, ok, "ci-gate has no check lines")
	checks, findings := parseGateChecks(wf.File, step)
	require.Empty(t, findings)
	return step, checks
}

// TestCIGateScriptFailsAScheduleRunTheGuardDidNotClear runs ci.yml's gate
// script with every job green: a schedule run passes only on the schedule
// guard's `run` (v1.29.3). A `busy` verdict never reaches the script, as the
// gate's if: skips it.
func TestCIGateScriptFailsAScheduleRunTheGuardDidNotClear(t *testing.T) {
	step, checks := loadGateStep(t)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	cases := []struct {
		name     string
		schedule string
		verdict  string
		wantPass bool
	}{
		{"a schedule run the guard cleared", "true", "run", true},
		{"a schedule run the guard could not read", "true", "unreadable", false},
		{"a schedule run whose verdict did not render", "true", "", false},
		{"a push, which the guard does not check", "false", "run", true},
		{"a push whose verdict did not render", "false", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{
				"PATH=" + os.Getenv("PATH"),
				fullTierEnv + "=true",
				docsOnlyEnv + "=false",
				draftEnv + "=false",
				nightlyEnv + "=" + tc.schedule,
				scheduleEnv + "=" + tc.schedule,
				scheduleGuardEnv + "=" + tc.verdict,
			}
			for _, c := range checks {
				env = append(env, c.EnvVar+"=success")
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
			require.Contains(t, string(out), "FAIL schedule-guard")
		})
	}
}

func TestCIGateScriptPassesASkipOnlyForAnUnselectedTier(t *testing.T) {
	step, checks := loadGateStep(t)

	varOf := func(tier string) string {
		idx := slices.IndexFunc(checks, func(c ciGateCheck) bool { return c.Tier == tier })
		require.GreaterOrEqual(t, idx, 0, "the gate checks no %s-tier job", tier)
		return checks[idx].EnvVar
	}
	prVar, docsVar, fullVar, nightlyVar := varOf(tierPR), varOf(tierDocs), varOf(tierFull), varOf(tierNightly)

	// A PR skips the nightly tier alongside the full tier.
	everyFullSkipped := make(map[string]string)
	everyDocsAndFullSkipped := make(map[string]string)
	everySkipped := make(map[string]string)
	for _, c := range checks {
		everySkipped[c.EnvVar] = "skipped"
		if c.Tier == tierFull || c.Tier == tierDocs || c.Tier == tierNightly {
			everyDocsAndFullSkipped[c.EnvVar] = "skipped"
		}
		if c.Tier == tierFull || c.Tier == tierNightly {
			everyFullSkipped[c.EnvVar] = "skipped"
		}
	}

	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	cases := []struct {
		name     string
		fullTier string
		docsOnly string
		results  map[string]string
		wantPass bool
		draft    bool
		nightly  string
	}{
		{"every job succeeded on a full-tier run", "true", "false", map[string]string{nightlyVar: "skipped"}, true, false, "false"},
		{"every job succeeded on a nightly run", "true", "false", nil, true, false, "true"},
		{"a nightly-tier job skipped on a nightly run", "true", "false", map[string]string{nightlyVar: "skipped"}, false, false, "true"},
		{"a nightly-tier job failed on a nightly run", "true", "false", map[string]string{nightlyVar: "failure"}, false, false, "true"},
		{"a nightly-tier job failed on a push", "true", "false", map[string]string{nightlyVar: "failure"}, false, false, "false"},
		{"the full tier skipped on an ordinary PR", "false", "false", everyFullSkipped, true, false, "false"},
		{"the docs and full tiers skipped on a docs-only PR", "false", "true", everyDocsAndFullSkipped, true, false, "false"},
		{"a full-tier job skipped although the full tier was selected", "true", "false", map[string]string{fullVar: "skipped"}, false, false, "false"},
		{"a full-tier job skipped while FULL_TIER did not render", "", "false", map[string]string{fullVar: "skipped"}, false, false, "false"},
		{"a pr-tier job skipped", "false", "false", map[string]string{prVar: "skipped"}, false, false, "false"},
		{"a pr-tier job skipped on a docs-only PR", "false", "true", map[string]string{prVar: "skipped"}, false, false, "false"},
		{"a docs-tier job skipped on a PR that is not docs-only", "false", "false", map[string]string{docsVar: "skipped"}, false, false, "false"},
		{"a docs-tier job skipped while DOCS_ONLY did not render", "false", "", map[string]string{docsVar: "skipped"}, false, false, "false"},
		{"a docs-tier job skipped on a run that selected the full tier", "true", "true", map[string]string{docsVar: "skipped"}, false, false, "false"},
		{"a docs-tier job failed on a docs-only PR", "false", "true", map[string]string{docsVar: "failure"}, false, false, "false"},
		{"a full-tier job failed on an ordinary PR", "false", "false", map[string]string{fullVar: "failure"}, false, false, "false"},
		{"a result that did not render", "false", "false", map[string]string{prVar: ""}, false, false, "false"},
		{"a draft PR whose jobs all succeeded", "false", "false", nil, false, true, "false"},
		{"a draft PR whose every job skipped", "false", "false", everySkipped, false, true, "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{
				fullTierEnv + "=" + tc.fullTier,
				docsOnlyEnv + "=" + tc.docsOnly,
				draftEnv + "=" + strconv.FormatBool(tc.draft),
				nightlyEnv + "=" + tc.nightly,
			}
			runGateScript(t, bash, step, checks, env, tc.results, tc.wantPass)
		})
	}
}

// runGateScript runs the gate's script under env, every check's result
// reading `success` unless results sets it, and asserts its verdict.
func runGateScript(t *testing.T, bash string, step ciStep, checks []ciGateCheck, env []string, results map[string]string, wantPass bool) {
	t.Helper()
	env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	for _, c := range checks {
		result, set := results[c.EnvVar]
		if !set {
			result = "success"
		}
		env = append(env, c.EnvVar+"="+result)
	}
	// -eo pipefail is the runner's default bash invocation for `run:`.
	cmd := exec.CommandContext(t.Context(), bash, "-eo", "pipefail", "-c", step.Run)
	cmd.Env = env
	out, runErr := cmd.CombinedOutput()
	if wantPass {
		require.NoError(t, runErr, string(out))
		return
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, runErr, &exitErr, "the gate passed:\n%s", out)
}

// TestCIGateScriptPassesAMainTierSkipOnlyOnAPullRequest runs the gate's
// script over a main-tier job (#1411): it skips on every pull request, so
// its skip passes there and nowhere else, and its failure never passes.
func TestCIGateScriptPassesAMainTierSkipOnlyOnAPullRequest(t *testing.T) {
	step, checks := loadGateStep(t)
	idx := slices.IndexFunc(checks, func(c ciGateCheck) bool { return c.Tier == tierMain })
	require.GreaterOrEqual(t, idx, 0, "the gate checks no main-tier job")
	mainVar := checks[idx].EnvVar

	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	cases := []struct {
		name        string
		pullRequest string
		result      string
		wantPass    bool
	}{
		{"a main-tier job skipped on a pull request", "true", "skipped", true},
		{"a main-tier job skipped on a push", "false", "skipped", false},
		{"a main-tier job skipped while PULL_REQUEST did not render", "", "skipped", false},
		{"a main-tier job failed on a push", "false", "failure", false},
		{"a main-tier job failed on a pull request", "true", "failure", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every other job succeeds, so the tier flags read as on a push.
			env := []string{
				fullTierEnv + "=true",
				docsOnlyEnv + "=false",
				draftEnv + "=false",
				nightlyEnv + "=false",
				pullRequestEnv + "=" + tc.pullRequest,
			}
			runGateScript(t, bash, step, checks, env, map[string]string{mainVar: tc.result}, tc.wantPass)
		})
	}
}

// fixtureTieredCI is a minimal consistent tiered workflow the negative cases
// below each break in one place.
const fixtureTieredCI = `on:
  pull_request:
    types: [opened, synchronize, reopened]
concurrency:
  group: ` + supersededGroup + `
  cancel-in-progress: true
env:
  CI_FULL_TIER: ` + ciFullTierEnvValue + `
jobs:
  lint:
    if: ` + prTierIf + `
    runs-on: x
  changes:
    if: ` + prTierIf + `
    runs-on: x
  build:
    if: ` + docsOnlyIf + `
    needs: [changes]
  race:
    if: ` + fullTierIf + `
    needs: lint
  fips:
    if: ` + mainOnlyIf + `
  soak:
    if: ` + nightlyIf + `
  schedule-guard:
    if: ` + prTierIf + `
    runs-on: x
  image:
    if: ` + prTierGuardedIf + `
    needs: [changes, schedule-guard]
    runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}
  ci-gate:
    if: ` + ciGateIf + `
    needs: [lint, changes, build, race, fips, soak, schedule-guard, image]
    steps:
      - env:
          FULL_TIER: ` + fullTierEnvValue + `
          DOCS_ONLY: ` + docsOnlyEnvValue + `
          DRAFT: ` + draftEnvValue + `
          NIGHTLY: ` + nightlyEnvValue + `
          PULL_REQUEST: ` + pullRequestEnvValue + `
          SCHEDULE: ` + scheduleEnvValue + `
          SCHEDULE_GUARD: ` + scheduleGuardEnvValue + `
          RESULT_LINT: ${{ needs.lint.result }}
          RESULT_CHANGES: ${{ needs.changes.result }}
          RESULT_SCHEDULE_GUARD: ${{ needs.schedule-guard.result }}
          RESULT_IMAGE: ${{ needs.image.result }}
          RESULT_BUILD: ${{ needs.build.result }}
          RESULT_RACE: ${{ needs.race.result }}
          RESULT_FIPS: ${{ needs.fips.result }}
          RESULT_SOAK: ${{ needs.soak.result }}
        run: |
          check pr lint "$RESULT_LINT"
          check pr changes "$RESULT_CHANGES"
          check pr schedule-guard "$RESULT_SCHEDULE_GUARD"
          check pr image "$RESULT_IMAGE"
          check docs build "$RESULT_BUILD"
          check full race "$RESULT_RACE"
          check nightly soak "$RESULT_SOAK"
          check main fips "$RESULT_FIPS"
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
		{"an unknown tier tag", `check pr lint`, `check fast lint`, `tier tag "fast" is none of`},
		{"a job with no check line", "          check pr lint \"$RESULT_LINT\"\n", "", "lint: no check line in ci-gate"},
		{"a job missing from the gate's needs", `race, fips,`, `fips,`, "race: not in ci-gate's needs"},
		{"a docs-tier job tagged pr", `check docs build`, `check pr build`, "build: tagged pr in ci-gate, but its if: puts it in the docs tier"},
		{"a pr-tier job tagged docs", `check pr lint`, `check docs lint`, "lint: tagged docs in ci-gate, but its if: puts it in the pr tier"},
		{"a docs-only if: that drifted", "!= 'true' &&", "!= true &&", "build: if: "},
		{"a docs-tier job that does not need changes", "    needs: [changes]\n", "    needs: [lint]\n", "build: a docs-tier job needs changes"},
		{"a docs tier without a changes job", "  changes:\n    if: " + prTierIf + "\n    runs-on: x\n", "", "the docs tier has no changes job"},
		{"a changes job missing from the gate's needs", `needs: [lint, changes, build`, `needs: [lint, build`, "changes: not in ci-gate's needs"},
		{"a changes job with no check line", "          check pr changes \"$RESULT_CHANGES\"\n", "", "changes: no check line in ci-gate"},
		{"a DOCS_ONLY that reads another output", `DOCS_ONLY: ${{ needs.changes.outputs.docs_only }}`, `DOCS_ONLY: ${{ needs.changes.outputs.docs }}`, "$DOCS_ONLY is"},
		{"a DOCS_ONLY that is missing", "          DOCS_ONLY: " + docsOnlyEnvValue + "\n", "", "$DOCS_ONLY is \"\""},
		{"a pr-tier job needing a docs-tier job", "    runs-on: x\n  changes:", "    runs-on: x\n    needs: build\n  changes:", "a PR-tier job needs docs-tier job build"},
		{"a docs-tier job needing a full-tier job", "    needs: [changes]\n", "    needs: [changes, race]\n", "a docs-tier job needs full-tier job race"},
		{"a full-tier if: that drifted", "'ci:full'))", "'ci-full'))", "race: if: "},
		{"a pr-tier job needing a full-tier job", "    runs-on: x\n  changes:", "    runs-on: x\n    needs: race\n  changes:", "a PR-tier job needs full-tier job race"},
		{"a check reading another job's result", `RESULT_RACE: ${{ needs.race.result }}`, `RESULT_RACE: ${{ needs.lint.result }}`, "$RESULT_RACE is"},
		{"a FULL_TIER that does not read CI_FULL_TIER", fullTierEnvValue, `${{ github.event_name == 'push' }}`, "$FULL_TIER is"},
		{"a CI_FULL_TIER that drifted from the jobs' if:", "CI_FULL_TIER: ${{ github.event_name != 'pull_request'", "CI_FULL_TIER: ${{ github.event_name == 'push'", "env: CI_FULL_TIER is"},
		{"a workflow without CI_FULL_TIER", "env:\n  CI_FULL_TIER: " + ciFullTierEnvValue + "\n", "", "env: CI_FULL_TIER is \"\""},
		{"a gate without the draft flag", "          DRAFT: " + draftEnvValue + "\n", "", "$DRAFT is \"\""},
		{"a draft flag that never reads true", draftEnvValue, `${{ github.event.pull_request.draft == 'true' }}`, "$DRAFT is"},
		{"a pr-tier job without the draft guard", "  lint:\n    if: " + prTierIf + "\n", "  lint:\n", `lint: if: "" is no tier`},
		{"a docs-tier job without the draft guard", "!= 'true' && " + draftGuard, "!= 'true'", "build: if: "},
		{"a full-tier job without the draft guard", "    if: " + fullTierIf + "\n    needs: lint", "    if: ${{ " + fullTierExpr + " }}\n    needs: lint", "race: if: "},
		{"a gate that does not always run", "if: " + ciGateIf, `if: success()`, `if: is "success()"`},
		{"a gate that runs on a busy schedule", "if: " + ciGateIf, `if: always()`, `if: is "always()"`},
		{"a bigdisk job without the schedule guard", "    if: " + prTierGuardedIf + "\n    needs: [changes, schedule-guard]", "    if: " + prTierIf + "\n    needs: [changes, schedule-guard]", "image: a bigdisk job's if: carries the schedule guard"},
		{"a bigdisk job whose guard drifted", "needs.schedule-guard.outputs.verdict == 'run') }}\n    needs: [changes", "needs.schedule-guard.outputs.verdict != 'busy') }}\n    needs: [changes", "image: if: "},
		{"a bigdisk job that does not need the schedule guard", `needs: [changes, schedule-guard]`, `needs: [changes]`, "image: its if: reads the schedule guard, so it needs schedule-guard"},
		{"a schedule guard missing from the gate's needs", `soak, schedule-guard, image]`, `soak, image]`, "schedule-guard: not in ci-gate's needs"},
		{"a schedule guard with no check line", "          check pr schedule-guard \"$RESULT_SCHEDULE_GUARD\"\n", "", "schedule-guard: no check line in ci-gate"},
		{"a workflow without the schedule guard job", "  schedule-guard:\n    if: " + prTierIf + "\n    runs-on: x\n", "", "the workflow has no schedule-guard job"},
		{"a gate without the schedule flag", "          SCHEDULE: " + scheduleEnvValue + "\n", "", "$SCHEDULE is \"\""},
		{"a schedule flag that reads another event", "SCHEDULE: " + scheduleEnvValue, "SCHEDULE: ${{ github.event_name == 'push' }}", "$SCHEDULE is"},
		{"a gate without the schedule guard's verdict", "          SCHEDULE_GUARD: " + scheduleGuardEnvValue + "\n", "", "$SCHEDULE_GUARD is \"\""},
		{"a verdict that reads the guard's result", "SCHEDULE_GUARD: " + scheduleGuardEnvValue, "SCHEDULE_GUARD: ${{ needs.schedule-guard.result }}", "$SCHEDULE_GUARD is"},
		{"a gate checking an undefined job", `check full race "$RESULT_RACE"`, "check full race \"$RESULT_RACE\"\n          check pr ghost \"$RESULT_RACE\"", "ghost: ci-gate checks a job the workflow does not define"},
		{"pull_request with the labeled type", `reopened]`, `reopened, labeled]`, "not on a label event"},
		{"pull_request with the ready_for_review type", `reopened]`, `reopened, ready_for_review]`, "not on a label event"},
		{"pull_request without the synchronize type", `synchronize, `, ``, "types are [opened reopened]"},
		{"a main-tier job missing from the gate's needs", `race, fips, soak,`, `race, soak,`, "fips: not in ci-gate's needs"},
		{"a main-tier job without a check line", "          check main fips \"$RESULT_FIPS\"\n", "", "fips: no check line in ci-gate"},
		{"a main-tier job tagged full", `check main fips`, `check full fips`, "fips: tagged full in ci-gate, but its if: puts it in the main tier"},
		{"a full-tier job tagged main", `check full race`, `check main race`, "race: tagged main in ci-gate, but its if: puts it in the full tier"},
		{"a main if: that drifted", "  fips:\n    if: " + mainOnlyIf + "\n", "  fips:\n    if: github.event_name == 'push'\n", "fips: if: "},
		{"a gate without the pull-request flag", "          PULL_REQUEST: " + pullRequestEnvValue + "\n", "", "$PULL_REQUEST is \"\""},
		{"a pull-request flag that reads another event", "PULL_REQUEST: " + pullRequestEnvValue, "PULL_REQUEST: ${{ github.event_name == 'push' }}", "$PULL_REQUEST is"},
		{"a full-tier job needing a main-tier job", "    needs: lint\n  fips:", "    needs: [lint, fips]\n  fips:", "race: a full-tier job needs main-tier job fips"},
		{"a nightly-tier job tagged full", `check nightly soak`, `check full soak`, "soak: tagged full in ci-gate, but its if: puts it in the nightly tier"},
		{"a full-tier job tagged nightly", `check full race`, `check nightly race`, "race: tagged nightly in ci-gate, but its if: puts it in the full tier"},
		{"a nightly if: that drifted", "  soak:\n    if: " + nightlyIf + "\n", "  soak:\n    if: ${{ github.event_name == 'schedule' }}\n", "soak: if: "},
		{"a nightly-tier job missing from the gate's needs", `fips, soak,`, `fips,`, "soak: not in ci-gate's needs"},
		{"a gate without the nightly flag", "          NIGHTLY: " + nightlyEnvValue + "\n", "", "$NIGHTLY is \"\""},
		{"a nightly flag that reads another event", "NIGHTLY: " + nightlyEnvValue, "NIGHTLY: ${{ github.event_name == 'push' }}", "$NIGHTLY is"},
		{"a full-tier job needing a nightly-tier job", "    needs: lint\n  fips:", "    needs: [lint, soak]\n  fips:", "a full-tier job needs nightly-tier job soak"},
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
	// The race check is the fixture's third-to-last line; the soak and fips
	// checks follow it.
	require.Equal(t, strings.Count(fixtureTieredCI, "\n")-2, tierErr.Line)
}

func TestConcurrencyFindingsRejectAnUncancellableGroup(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"an expression for cancel-in-progress", `cancel-in-progress: true`, `cancel-in-progress: ${{ true }}`, "must be the literal true"},
		{"a main-only expression for cancel-in-progress", `cancel-in-progress: true`, `cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}`, "must be the literal true"},
		{"cancel-in-progress false", `cancel-in-progress: true`, `cancel-in-progress: false`, "must be the literal true"},
		{"a group with no ref", supersededGroup, `${{ github.workflow }}`, "group must be"},
		{"a ref-only group lets a main push cancel main", supersededGroup, `${{ github.workflow }}-${{ github.ref }}`, "group must be"},
		{"a sha-only group never supersedes a PR run", supersededGroup, `${{ github.workflow }}-${{ github.sha }}`, "group must be"},
		{"a run_id group on main", supersededGroup, `${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && github.run_id || github.ref }}`, "group must be"},
		{"a main group without the event", "format('main-{0}-{1}', github.event_name, github.sha)", "github.sha", "group must be"},
		{"a per-commit group on a branch other than main", `'refs/heads/main'`, `'refs/heads/dev'`, "group must be"},
		{"a per-ref group on main with a per-commit group elsewhere", supersededGroup, `${{ github.workflow }}-${{ github.ref != 'refs/heads/main' && github.sha || github.ref }}`, "group must be"},
		{"a schedule run that takes a main or ref group", supersededGroup, `${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}`, "group must be"},
		{"a schedule group keyed by commit", "format('schedule-{0}', github.repository)", "format('schedule-{0}-{1}', github.repository, github.sha)", "group must be"},
		{"a schedule group tested after the main group", supersededGroup, `${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.event_name == 'schedule' && format('schedule-{0}', github.repository) || github.ref }}`, "group must be"},
		{"no concurrency block", "concurrency:\n  group: " + supersededGroup + "\n  cancel-in-progress: true\n", "", "has no concurrency block"},
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
