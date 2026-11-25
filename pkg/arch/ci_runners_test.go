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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	// hostedRunner is where every ci.yml job runs unless it is waived off
	// (ruling 1006): the standard GitHub-hosted runner.
	hostedRunner = "ubuntu-latest"
	// selfHostedWaiver opens the waiver a job that leaves hostedRunner
	// carries in its runs-on line comment, followed by a category and a
	// measured reason.
	selfHostedWaiver = "# self-hosted: "
)

// waiverCategories are the categories a ci.yml waiver may name: the job
// needs specific hardware, or it needs more than a standard hosted runner's
// 4 vCPU, 16 GB memory, about 14 GB free disk or 6 hours. `credential:` is
// only for the Codex review job in code-review.yml, never in ci.yml.
var waiverCategories = []string{"hardware", "oversize"}

// runnerJob is one ci.yml job's runs-on node.
type runnerJob struct {
	name   string
	runsOn *yaml.Node
	cond   string // the job-level if:, "" when there is none
}

// runnerJobs parses ci.yml and returns its jobs in order, or a problem.
func runnerJobs(body []byte) ([]runnerJob, string) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return nil, "ci.yml does not parse: " + errString(err)
	}
	jobs := mapValue(doc.Content[0], "jobs")
	if jobs == nil || len(jobs.Content) == 0 {
		return nil, "ci.yml has no jobs"
	}
	var out []runnerJob
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		j := runnerJob{name: jobs.Content[i].Value, runsOn: mapValue(jobs.Content[i+1], "runs-on")}
		if c := mapValue(jobs.Content[i+1], "if"); c != nil {
			j.cond = c.Value
		}
		out = append(out, j)
	}
	return out, ""
}

// waiverProblem checks the self-hosted waiver in a runs-on line comment and
// returns "" when it names an allowed category and a non-empty reason.
func waiverProblem(comment string) string {
	i := strings.Index(comment+" ", strings.TrimSpace(selfHostedWaiver)+" ")
	if i < 0 {
		return "carries no `" + selfHostedWaiver + "hardware: <reason>` or `" + selfHostedWaiver + "oversize: <reason>` waiver"
	}
	rest := strings.TrimSpace(comment[i+len(strings.TrimSpace(selfHostedWaiver)):])
	category, reason, ok := strings.Cut(rest, ":")
	category = strings.TrimSpace(category)
	switch {
	case ok && category == "credential":
		return "has a credential: waiver, which only the Codex review job in code-review.yml may carry"
	case !ok || !slices.Contains(waiverCategories, category):
		return "has a waiver that names no category: want `" + selfHostedWaiver + "hardware: <reason>` or `" + selfHostedWaiver + "oversize: <reason>`, got " + strconv.Quote(comment)
	case strings.TrimSpace(reason) == "":
		return "has a " + category + ": waiver with an empty reason"
	}
	return ""
}

// runnerProblems lists every ci.yml job whose runs-on breaks the runner
// rule, given the workflow's text: a job runs on hostedRunner, or on a
// self-hosted label with a categorised waiver, and never on an expression,
// which can pick a self-hosted label.
func runnerProblems(body []byte) []string {
	jobs, problem := runnerJobs(body)
	if problem != "" {
		return []string{problem}
	}
	var problems []string
	for _, j := range jobs {
		where := "job " + j.name
		switch {
		case j.runsOn == nil:
			problems = append(problems, where+" has no runs-on")
		case j.runsOn.Kind != yaml.ScalarNode:
			problems = append(problems, where+" runs on a label list; every job runs on "+hostedRunner+" or one self-hosted label with a waiver")
			if p := waiverProblem(j.runsOn.LineComment); p != "" {
				problems = append(problems, where+" "+p)
			}
		case isSelectionRunsOn(j.runsOn.Value):
			// v1.48: the preflight selection, hosted unless the hosted
			// pool is full; its step keeps fork pull requests hosted.
		case j.name == "preflight" && j.runsOn.Value == selectionPreflight:
			// Its expression keeps fork pull requests and other events hosted.
		case strings.Contains(j.runsOn.Value, "${{"):
			problems = append(problems, where+" runs on an expression, which can pick a self-hosted label: "+strconv.Quote(j.runsOn.Value))
		case j.runsOn.Value != hostedRunner:
			if p := waiverProblem(j.runsOn.LineComment); p != "" {
				problems = append(problems, where+" runs on "+strconv.Quote(j.runsOn.Value)+" and "+p)
			}
		}
		// A self-hosted runner is persistent: fork pull requests must
		// never reach it, so the job's if: carries the same-repository guard.
		if j.runsOn != nil && (j.runsOn.Kind != yaml.ScalarNode || (j.runsOn.Value != hostedRunner && !isSelectionRunsOn(j.runsOn.Value) && (j.name != "preflight" || j.runsOn.Value != selectionPreflight))) &&
			!strings.Contains(j.cond, sameRepoExpr) {
			problems = append(problems, where+": self-hosted runner without the fork guard")
		}
	}
	return problems
}

// mapValue returns the value of key in the mapping n, or nil.
func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return "empty document"
	}
	return err.Error()
}

func readCI(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	return b
}

// TestCIRunsHostedFirst holds the runner rule on ci.yml: every job runs on
// hostedRunner, or on one self-hosted label whose runs-on line carries a
// categorised waiver.
func TestCIRunsHostedFirst(t *testing.T) {
	for _, p := range runnerProblems(readCI(t)) {
		t.Error(p)
	}
}

// TestWebE2EPlaywrightHostOverride pins the web-e2e job's Playwright host
// override (DS-10151): ubuntu-latest is the 26.04 image, for which the pinned
// Playwright has no chromium build, so the job installs and runs the 24.04 one.
func TestWebE2EPlaywrightHostOverride(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal(readCI(t), &doc); err != nil || len(doc.Content) == 0 {
		t.Fatalf("ci.yml does not parse: %s", errString(err))
	}
	job := mapValue(mapValue(doc.Content[0], "jobs"), "web-e2e")
	if job == nil {
		t.Fatal("ci.yml has no web-e2e job")
	}
	const key, want = "PLAYWRIGHT_HOST_PLATFORM_OVERRIDE", "ubuntu24.04-x64"
	v := mapValue(mapValue(job, "env"), key)
	if v == nil {
		t.Fatalf("web-e2e env has no %s; want %q", key, want)
	}
	if v.Value != want {
		t.Fatalf("web-e2e env %s = %q, want %q", key, v.Value, want)
	}
}

// The v1.48 runner selection (ci-template v1.48, Tenant Agent rulings 1024
// and 1031, #2128): the preflight step `Hosted or overflow runner (ruling
// 1024)` decides once per run whether its jobs run on the GitHub-hosted
// default or overflow to the self-hosted overflow runners, and every hosted
// job reads that decision. Off github.com each job keeps its label.
const (
	selectionStep        = "Hosted or overflow runner (ruling 1024)"
	selectionRunner      = "${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner) || 'ubuntu-latest' }}"
	selectionDocker      = "${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'ubuntu-latest' }}"
	selectionGate        = "${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner || '\"ubuntu-latest\"') || 'ubuntu-latest' }}"
	selectionForkEvents  = "case \"$EVENT\" in\n  pull_request|pull_request_target)\n"
	selectionForkGuard   = `if [ "$HEAD_REPO" != "$REPO" ]; then`
	selectionOverflowMsg = "the self-hosted overflow runners (bigdisk, bigdisk-docker)"
	// selectionPreflight is preflight's runs-on: the bigdisk pool, or
	// CI_PREFLIGHT_RUNS_ON, on a push to main or a same-repository pull
	// request, the only events the self-hosted runners accept; hosted on
	// every other event and off github.com.
	selectionPreflight = `${{ github.server_url == 'https://github.com' && ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`
)

// selectionRunsOn is the runs-on every job of ci.yml carries under v1.48:
// a job whose steps run Docker reads runner_docker, CI Gate reads runner with
// the hosted fallback, the others read runner. preflight takes
// selectionPreflight; image keeps its ruling 999 oversize waiver.
var selectionRunsOn = map[string]string{
	"preflight":  selectionPreflight,
	"lint":       selectionDocker,
	"image":      "bigdisk-docker",
	"lint-gates": selectionRunner,
	"sdkjs":      selectionRunner,
	"race":       selectionRunner,
	"web":        selectionRunner,
	// Hosted only: `playwright install --with-deps` installs system packages.
	"web-e2e":           hostedRunner,
	"integration-image": selectionDocker,
	"integration":       selectionDocker,
	"soak":              selectionDocker,
	"fips":              selectionRunner,
	"signatures":        selectionRunner,
	"ci-gate":           selectionGate,
}

// isSelectionRunsOn reports whether runsOn is one of the v1.48 forms.
func isSelectionRunsOn(runsOn string) bool {
	return runsOn == selectionRunner || runsOn == selectionDocker || runsOn == selectionGate
}

// selectionProblems lists every way ci.yml departs from the v1.48 runner
// selection.
func selectionProblems(body []byte) []string {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return []string{"ci.yml does not parse: " + errString(err)}
	}
	root := doc.Content[0]
	var problems []string
	env := mapValue(root, "env")
	for key, want := range map[string]string{"HOSTED_JOBS_PER_REPO": "12", "HOSTED_QUEUE_GRACE_SECONDS": "60"} {
		if v := mapValue(env, key); v == nil || v.Value != want {
			problems = append(problems, "env "+key+" is not "+want)
		}
	}
	jobs := mapValue(root, "jobs")
	if jobs == nil {
		return append(problems, "ci.yml has no jobs")
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		seen[name] = true
		want, known := selectionRunsOn[name]
		if !known {
			problems = append(problems, "job "+name+" has no v1.48 runner in this test")
			continue
		}
		runsOn := mapValue(job, "runs-on")
		if runsOn == nil || runsOn.Kind != yaml.ScalarNode || runsOn.Value != want {
			got := "<none>"
			if runsOn != nil {
				got = runsOn.Value
			}
			problems = append(problems, "job "+name+" runs on "+strconv.Quote(got)+", want "+strconv.Quote(want))
		}
		if !isSelectionRunsOn(want) {
			continue
		}
		needsPreflight := false
		if needs := mapValue(job, "needs"); needs != nil {
			needsPreflight = needs.Value == "preflight"
			for _, n := range needs.Content {
				needsPreflight = needsPreflight || n.Value == "preflight"
			}
		}
		if !needsPreflight {
			problems = append(problems, "job "+name+" reads needs.preflight.outputs but does not need preflight")
		}
	}
	for name := range selectionRunsOn {
		if !seen[name] {
			problems = append(problems, "job "+name+" is missing")
		}
	}
	preflight := mapValue(jobs, "preflight")
	outputs := mapValue(preflight, "outputs")
	for key, want := range map[string]string{
		"runner":        "${{ steps.runner.outputs.runner }}",
		"runner_docker": "${{ steps.runner.outputs.runner_docker }}",
	} {
		if v := mapValue(outputs, key); v == nil || v.Value != want {
			problems = append(problems, "preflight output "+key+" is not "+want)
		}
	}
	if p := mapValue(mapValue(preflight, "permissions"), "actions"); p == nil || p.Value != "read" {
		problems = append(problems, "preflight lacks actions: read")
	}
	steps := mapValue(preflight, "steps")
	if steps == nil || len(steps.Content) == 0 {
		return append(problems, "preflight has no steps")
	}
	first := steps.Content[0]
	if n := mapValue(first, "name"); n == nil || n.Value != selectionStep {
		problems = append(problems, "preflight's first step, before any checkout, is not "+strconv.Quote(selectionStep))
	}
	if id := mapValue(first, "id"); id == nil || id.Value != "runner" {
		problems = append(problems, "the selection step's id is not runner")
	}
	run := ""
	if r := mapValue(first, "run"); r != nil {
		run = r.Value
	}
	for _, want := range []string{selectionForkEvents + "    " + selectionForkGuard, selectionOverflowMsg, `emit "$(overflow bigdisk)" "$(overflow bigdisk-docker)"`} {
		if !strings.Contains(run, want) {
			problems = append(problems, "the selection step's run lacks "+strconv.Quote(want))
		}
	}
	return problems
}

func TestCIJobsReadThePreflightRunnerSelection(t *testing.T) {
	for _, p := range selectionProblems(readCI(t)) {
		t.Error(p)
	}
}

func TestSelectionProblems_Mutations(t *testing.T) {
	body := string(readCI(t))
	if p := selectionProblems([]byte(body)); len(p) != 0 {
		t.Fatalf("ci.yml itself has problems: %v", p)
	}
	for _, c := range []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"a hosted job back on a plain label", func(b string) string { return replaceJobRunner(t, b, "race", hostedRunner) }, "job race runs on"},
		{"a Docker job reading runner", func(b string) string { return replaceJobRunner(t, b, "integration", selectionRunner) }, "job integration runs on"},
		{"the gate without its fallback", func(b string) string { return replaceJobRunner(t, b, "ci-gate", selectionRunner) }, "job ci-gate runs on"},
		{"another limit", func(b string) string {
			return strings.Replace(b, "HOSTED_JOBS_PER_REPO: 12", "HOSTED_JOBS_PER_REPO: 20", 1)
		}, "env HOSTED_JOBS_PER_REPO is not 12"},
		{"another grace", func(b string) string {
			return strings.Replace(b, "HOSTED_QUEUE_GRACE_SECONDS: 60", "HOSTED_QUEUE_GRACE_SECONDS: 5", 1)
		}, "env HOSTED_QUEUE_GRACE_SECONDS is not 60"},
		{"the fork guard dropped", func(b string) string { return strings.Replace(b, selectionForkGuard, "if false; then", 1) }, "lacks"},
		{"the step renamed", func(b string) string { return strings.Replace(b, "name: "+selectionStep, "name: Runner", 1) }, "first step"},
	} {
		t.Run(c.name, func(t *testing.T) {
			mutated := c.mutate(body)
			if mutated == body {
				t.Fatal("the mutation changed nothing")
			}
			p := selectionProblems([]byte(mutated))
			if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, c.want) }) {
				t.Fatalf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
}

// TestRunnerProblems_Mutations shows that runnerProblems reports each
// regression of ci.yml's runners, and accepts a categorised waiver.
func TestRunnerProblems_Mutations(t *testing.T) {
	body := string(readCI(t))
	if p := runnerProblems([]byte(body)); len(p) != 0 {
		t.Fatalf("ci.yml itself has problems: %v", p)
	}
	lint := func(runsOn string) func(string) string {
		return func(b string) string { return replaceJobRunner(t, b, "lint", runsOn) }
	}
	guarded := func(mutate func(string) string) func(string) string {
		return func(b string) string { return replaceJobIf(t, mutate(b), "lint", "${{ "+sameRepoExpr+" }}") }
	}
	const split = `${{ ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON('["self-hosted","linux","x64","bigdisk-docker"]') || 'ubuntu-latest' }}`
	for _, c := range []struct {
		name   string
		mutate func(string) string
		want   string // "" when the mutation is allowed
	}{
		{"a job sent to a self-hosted label", lint("bigdisk"), "job lint runs on \"bigdisk\" and carries no"},
		{"a job sent to a self-hosted label list", lint("[self-hosted, linux, x64, bigdisk]"), "job lint runs on a label list"},
		{"the event expression put back", func(b string) string {
			return replaceJobRunner(t, b, "race", split+"  "+selfHostedWaiver+"oversize: measured 24.2 GB")
		}, "job race runs on an expression"},
		{"preflight's expression on another job", lint(selectionPreflight), "job lint runs on an expression"},
		{"the Gitea release arm put back", func(b string) string {
			return replaceJobRunner(t, b, "web", `${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'release' }}`)
		}, "job web runs on an expression"},
		{"a bare waiver", lint("bigdisk  " + selfHostedWaiver + "needs a big disk"), "names no category"},
		{"a credential waiver", lint("bigdisk  " + selfHostedWaiver + "credential: the token is here"), "credential: waiver"},
		{"a waiver with an empty reason", lint("bigdisk  " + selfHostedWaiver + "hardware: "), "hardware: waiver with an empty reason"},
		{"a waiver with an empty oversize reason", lint("bigdisk  " + selfHostedWaiver + "oversize:"), "oversize: waiver with an empty reason"},
		{"a waiver with neither category nor reason", lint("bigdisk  " + selfHostedWaiver), "names no category"},
		{"a hardware waiver is allowed", guarded(lint("gpu  " + selfHostedWaiver + "hardware: needs the GPU host")), ""},
		{"an oversize waiver is allowed", guarded(lint("bigdisk  " + selfHostedWaiver + "oversize: measured 40 GB of disk")), ""},
		{"a self-hosted job without the fork guard", func(b string) string {
			return replaceJobIf(t, b, "image", docsOnlyGuardedIf)
		}, "job image: self-hosted runner without the fork guard"},
		{"a self-hosted job on bigdisk-docker without the fork guard", func(b string) string {
			return replaceJobIf(t, lint("bigdisk-docker  "+selfHostedWaiver+"oversize: measured 40 GB of disk")(b), "lint", "${{ github.event_name != 'schedule' }}")
		}, "job lint: self-hosted runner without the fork guard"},
		{"a self-hosted job with only the fork guard is allowed", func(b string) string {
			return replaceJobIf(t, b, "image", "${{ "+sameRepoExpr+" }}")
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			mutated := c.mutate(body)
			if mutated == body {
				t.Fatal("the mutation changed nothing")
			}
			p := runnerProblems([]byte(mutated))
			if c.want == "" {
				if len(p) != 0 {
					t.Fatalf("want no problem, got %v", p)
				}
				return
			}
			if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, c.want) }) {
				t.Fatalf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
}

// TestRunnerProblems_Unparsable shows a broken or empty workflow is reported.
func TestRunnerProblems_Unparsable(t *testing.T) {
	for in, want := range map[string]string{"jobs: [": "does not parse", "on: push\n": "has no jobs"} {
		if p := runnerProblems([]byte(in)); len(p) != 1 || !strings.Contains(p[0], want) {
			t.Errorf("runnerProblems(%q) = %v; want one problem containing %q", in, p, want)
		}
	}
}

// replaceJobRunner replaces the runs-on line of job in the workflow text.
func replaceJobRunner(t *testing.T, body, job, runsOn string) string {
	t.Helper()
	start := strings.Index(body, "\n  "+job+":\n")
	if start < 0 {
		t.Fatalf("ci.yml has no job %s", job)
	}
	i := strings.Index(body[start:], "    runs-on: ") + start
	end := strings.Index(body[i:], "\n") + i
	return body[:i] + "    runs-on: " + runsOn + body[end:]
}

// replaceJobIf sets (or adds) the job-level if: of job in the ci.yml body.
func replaceJobIf(t *testing.T, body, job, cond string) string {
	t.Helper()
	start := strings.Index(body, "\n  "+job+":\n")
	if start < 0 {
		t.Fatalf("ci.yml has no job %s", job)
	}
	lines := strings.Split(body[start+1:], "\n")
	for k, l := range lines[1:] {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
			break // the next job
		}
		if strings.HasPrefix(l, "    if: ") {
			lines[k+1] = "    if: " + cond
			return body[:start+1] + strings.Join(lines, "\n")
		}
	}
	// No job-level if: yet, so add one under the job name.
	return body[:start+1] + lines[0] + "\n    if: " + cond + "\n" + strings.Join(lines[1:], "\n")
}
