package arch

// Behavioural tests of ci.yml's runner selection (ci-template v1.60, the
// step `Balanced runner pool (ruling 1137)`). The run: script of
// the preflight step `id: runner` is taken from ci.yml as is and run with
// bash against fixture Actions API replies. A stub curl first on PATH serves
// the replies from files and logs every URL it is asked for, so the test
// makes no network call; jq, sort and bash are the host's. The step's
// runner and runner_docker outputs are read back from GITHUB_OUTPUT.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	selRepo     = "owner/repo"
	selAPI      = "https://api.github.invalid/repos/" + selRepo + "/actions"
	selRunID    = 1000
	selHosted   = `"ubuntu-latest"`
	selOverflow = `["self-hosted","linux","x64","bigdisk"]`
	selOverDock = `["self-hosted","linux","x64","bigdisk-docker"]`
)

// selStubCurl answers `curl ... -o FILE -w FMT URL` from $SEL_FIXTURES:
// <key>.exit makes curl fail with that exit status, <key>.code is the HTTP
// code (404 when absent) and <key>.json the body, where <key> is the URL
// with every byte outside [A-Za-z0-9] replaced by `_`.
const selStubCurl = `out= url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-w|-H|--max-time) [ "$1" = -o ] && out=$2; shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "$SEL_FIXTURES/calls.log"
key=${url//[^A-Za-z0-9]/_}
if [ -f "$SEL_FIXTURES/$key.exit" ]; then exit "$(< "$SEL_FIXTURES/$key.exit")"; fi
code=404
[ -f "$SEL_FIXTURES/$key.code" ] && code=$(< "$SEL_FIXTURES/$key.code")
if [ -f "$SEL_FIXTURES/$key.json" ]; then cp "$SEL_FIXTURES/$key.json" "$out"; else printf '{"message":"Not Found"}' > "$out"; fi
printf '%s' "$code"
`

// selStubGh fails any gh call: the step must not use one.
const selStubGh = `printf 'gh %s\n' "$*" >> "$SEL_FIXTURES/calls.log"; exit 99
`

var selKeyRe = regexp.MustCompile(`[^A-Za-z0-9]`)

// selJob is one job of the fixture: its run, status, runner labels and how
// long ago it was created.
type selJob struct {
	run    int
	status string
	labels []string
	age    time.Duration
}

// selReply is one fixture API reply.
type selReply struct {
	code int    // HTTP code; 0 with exit set means curl fails
	exit int    // curl's exit status, when it fails
	body string // the JSON body
}

var (
	selUbuntu     = []string{"ubuntu-latest"}
	selSelfHosted = []string{"self-hosted", "linux", "x64", "bigdisk"}
	selDocker     = []string{"self-hosted", "linux", "x64", "bigdisk-docker"}
)

// selJobs returns n jobs of run with the given status and labels, created
// age ago.
func selJobs(n, run int, status string, labels []string, age time.Duration) []selJob {
	out := make([]selJob, n)
	for i := range out {
		out[i] = selJob{run: run, status: status, labels: labels, age: age}
	}
	return out
}

// selPage is the URL of page p of a listing.
func selPage(listing string, p int) string {
	return fmt.Sprintf("%s&per_page=100&page=%d", listing, p)
}

// selPaged adds the 100-item pages of items under key at listing to replies.
func selPaged(replies map[string]selReply, listing, key string, items []any) {
	p := 1
	for {
		end := min(len(items), p*100)
		page := items[(p-1)*100 : end]
		if page == nil {
			page = []any{}
		}
		b, _ := json.Marshal(map[string]any{"total_count": len(items), key: page})
		replies[selPage(listing, p)] = selReply{code: 200, body: string(b)}
		if end >= len(items) {
			return
		}
		p++
	}
}

// selFixture builds the API replies for jobs: a run is listed as
// in_progress when any of its jobs is, else as queued; each run's jobs are
// listed with filter=latest, 100 to a page.
func selFixture(jobs []selJob) map[string]selReply {
	now := time.Now().UTC().Truncate(time.Second)
	byRun := map[int][]any{}
	running := map[int]bool{}
	for i, j := range jobs {
		byRun[j.run] = append(byRun[j.run], map[string]any{
			"id":         i + 1,
			"run_id":     j.run,
			"status":     j.status,
			"labels":     j.labels,
			"created_at": now.Add(-j.age).Format("2006-01-02T15:04:05Z"),
		})
		running[j.run] = running[j.run] || j.status == "in_progress"
	}
	runs := map[string][]any{"queued": {}, "in_progress": {}}
	ids := make([]int, 0, len(byRun))
	for id := range byRun {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	replies := map[string]selReply{}
	for _, id := range ids {
		st := "queued"
		if running[id] {
			st = "in_progress"
		}
		runs[st] = append(runs[st], map[string]any{"id": id, "status": st})
		selPaged(replies, fmt.Sprintf("%s/runs/%d/jobs?filter=latest", selAPI, id), "jobs", byRun[id])
	}
	for st, list := range runs {
		selPaged(replies, selAPI+"/runs?status="+st, "workflow_runs", list)
	}
	return replies
}

// selStep is the selection step of ci.yml: its run: script and env keys.
type selStep struct {
	run string
	env []string
}

// readSelStep extracts the preflight step `id: runner` from ci.yml.
func readSelStep(t *testing.T, body []byte) selStep {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		t.Fatalf("ci.yml does not parse: %s", errString(err))
	}
	steps := mapValue(mapValue(mapValue(doc.Content[0], "jobs"), "preflight"), "steps")
	if steps == nil {
		t.Fatal("ci.yml has no preflight steps")
	}
	for _, s := range steps.Content {
		if id := mapValue(s, "id"); id == nil || id.Value != "runner" {
			continue
		}
		var st selStep
		if r := mapValue(s, "run"); r != nil {
			st.run = r.Value
		}
		if env := mapValue(s, "env"); env != nil {
			for i := 0; i < len(env.Content); i += 2 {
				st.env = append(st.env, env.Content[i].Value)
			}
		}
		if st.run == "" {
			t.Fatal("the preflight step id: runner has no run: script")
		}
		return st
	}
	t.Fatal("ci.yml's preflight has no step with id: runner")
	return selStep{}
}

// selResult is what one run of the step left behind.
type selResult struct {
	rc            int
	stdout        string
	runner        string
	runnerDocker  string
	calls         []string
	outputEntries int
}

// selEnv is the step env of a case; the keys match the step's env: block.
// vars overrides the repository variables HS, C1 and C2 (12, 4 and 4) and
// ML and MLD (ci-template v1.63, empty).
type selEnv struct {
	server, event, headRepo, ref string
	vars                         map[string]string
	// private: the repository is private (PRIVATE=true); the default is a
	// public repository, PRIVATE=false (v1.62 overflow applies).
	private bool
}

// runSel runs script with the fixture replies and env and returns its result.
func runSel(t *testing.T, script string, replies map[string]selReply, e selEnv) selResult {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required: %v", err)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("jq is required (the step runs it): %v", err)
	}
	dir := t.TempDir()
	fix, bin, tmp := filepath.Join(dir, "fix"), filepath.Join(dir, "bin"), filepath.Join(dir, "tmp")
	for _, d := range []string{fix, bin, tmp} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "curl"), "#!"+bash+"\n"+selStubCurl, 0o755)
	write(filepath.Join(bin, "gh"), "#!"+bash+"\n"+selStubGh, 0o755)
	for url, r := range replies {
		key := filepath.Join(fix, selKeyRe.ReplaceAllString(url, "_"))
		if r.exit != 0 {
			write(key+".exit", fmt.Sprint(r.exit), 0o644)
			continue
		}
		write(key+".code", fmt.Sprint(r.code), 0o644)
		write(key+".json", r.body, 0o644)
	}
	write(filepath.Join(fix, "calls.log"), "", 0o644)
	output := filepath.Join(dir, "github_output")
	write(output, "", 0o644)
	stepFile := filepath.Join(dir, "step.sh")
	write(stepFile, script, 0o644)

	// GitHub's default shell for run: on Linux.
	cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", stepFile)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + dir,
		"SEL_FIXTURES=" + fix,
		"RUNNER_TEMP=" + tmp,
		"GITHUB_OUTPUT=" + output,
		"SERVER=" + e.server,
		"API=" + selAPI,
		"RUN_ID=" + fmt.Sprint(selRunID),
		"JOB_TOKEN=fixture-token",
		"REPO=" + selRepo,
		"HEAD_REPO=" + e.headRepo,
		"EVENT=" + e.event,
		"REF=" + e.ref,
		"PRIVATE=" + fmt.Sprint(e.private),
		"WAIT_LIMIT=600",
	}
	for k, v := range map[string]string{"HS": "12", "C1": "4", "C2": "4", "ML": "", "MLD": ""} {
		if o, ok := e.vars[k]; ok {
			v = o
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	res := selResult{stdout: string(out)}
	if ee, ok := err.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run the step: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(got)), "\n") {
		if line == "" {
			continue
		}
		res.outputEntries++
		switch k, v, _ := strings.Cut(line, "="); k {
		case "runner":
			res.runner = v
		case "runner_docker":
			res.runnerDocker = v
		}
	}
	calls, err := os.ReadFile(filepath.Join(fix, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	res.calls = strings.Fields(string(calls))
	return res
}

// TestRunnerSelectionStepEnv pins the env the step reads to the env this
// test sets, so a new input of the script is not left at its zero value, and
// the limits to the repository variables the Infra Department sets.
func TestRunnerSelectionStepEnv(t *testing.T) {
	got := readSelStep(t, readCI(t)).env
	sort.Strings(got)
	want := []string{"API", "C1", "C2", "EVENT", "HEAD_REPO", "HS", "JOB_TOKEN", "ML", "MLD", "PRIVATE", "REF", "REPO", "RUN_ID", "SERVER", "WAIT_LIMIT"}
	if !slices.Equal(got, want) {
		t.Fatalf("the selection step's env keys are %v; this test sets %v", got, want)
	}
	body := string(readCI(t))
	for _, v := range []string{"HS: ${{ vars.CI_HOSTED_SHARE }}", "C1: ${{ vars.CI_SELF_HOSTED_BIGDISK }}", "C2: ${{ vars.CI_SELF_HOSTED_BIGDISK_DOCKER }}", "PRIVATE: ${{ github.event.repository.private }}", "WAIT_LIMIT: 600", "ML: ${{ vars.CI_MAIN_RUNNER_LABEL }}", "MLD: ${{ vars.CI_MAIN_RUNNER_LABEL_DOCKER }}"} {
		if !strings.Contains(body, v) {
			t.Errorf("the selection step does not read %q", v)
		}
	}
}

// TestRunnerSelectionScript runs the real selection script against each
// fixture and checks the pool it picks: with HS=12 and C1=C2=4, the less-used
// pool, a tie to the self-hosted pool; one pool full, the other; both full,
// fewer queued, a tie to the self-hosted pool.
func TestRunnerSelectionScript(t *testing.T) {
	script := readSelStep(t, readCI(t)).run
	const (
		hosted   = "hosted"
		selfPool = "self-hosted"
		main     = "refs/heads/main"
		prRef    = "refs/pull/1/merge"
		forkNote = "head repository is not this repository (a fork)"
		refused  = "only a push to refs/heads/main or a pull request from this repository may reach a self-hosted runner"
	)
	gh := func(event, ref, headRepo string) selEnv {
		return selEnv{server: "https://github.com", event: event, ref: ref, headRepo: headRepo}
	}
	push := gh("push", main, "")
	private := push
	private.private = true
	vars := func(k, v string) selEnv { e := push; e.vars = map[string]string{k: v}; return e }
	h := func(n int, st string) []selJob { return selJobs(n, 7, st, selUbuntu, time.Minute) }
	s1 := func(n int, st string) []selJob { return selJobs(n, 8, st, selSelfHosted, time.Minute) }
	s2 := func(n int, st string) []selJob { return selJobs(n, 8, st, selDocker, time.Minute) }
	self := selJobs(1, selRunID, "in_progress", selSelfHosted, 5*time.Second) // this preflight job
	hostedFull := slices.Concat(self, h(12, "in_progress"))
	// 150 jobs of one run: the 12 in progress on the second page, so only a
	// complete read sees the hosted pool full.
	paged := slices.Concat(self, s1(1, "in_progress"), selJobs(138, 9, "completed", selUbuntu, time.Hour), selJobs(12, 9, "in_progress", selUbuntu, time.Minute))
	jobsURL := func(run, page int) string {
		return selPage(fmt.Sprintf("%s/runs/%d/jobs?filter=latest", selAPI, run), page)
	}
	runsURL := func(st string, page int) string { return selPage(selAPI+"/runs?status="+st, page) }

	for _, c := range []struct {
		name    string
		env     selEnv
		jobs    []selJob
		break_  func(map[string]selReply)
		want    string
		warning bool   // a ::warning names why there is no count
		notice  string // a ::notice line contains it
		noCalls bool   // the step must not call the API
		notCall string // no called URL contains it
	}{
		// Both pools below their limit: the lower use wins, a tie self-hosted.
		{name: "an idle repository: a tie", env: push, jobs: self, want: selfPool, notice: "use hosted 0/12, bigdisk 0/4, bigdisk-docker 0/4"},
		{name: "hosted busier", env: push, jobs: slices.Concat(self, h(3, "in_progress")), want: selfPool},
		{name: "equal use: a tie", env: push, jobs: slices.Concat(self, h(3, "in_progress"), s1(1, "in_progress")), want: selfPool, notice: "use hosted 3/12, bigdisk 1/4"},
		{name: "the self-hosted pool busier", env: push, jobs: slices.Concat(self, h(1, "in_progress"), s1(1, "in_progress")), want: hosted},
		{name: "bigdisk-docker above hosted use", env: push, jobs: slices.Concat(self, h(6, "in_progress"), s2(3, "in_progress")), want: hosted},
		{name: "queued jobs count as use", env: push, jobs: slices.Concat(self, h(1, "in_progress"), s1(1, "queued")), want: hosted},
		{name: "completed jobs are not counted", env: push, jobs: slices.Concat(self, h(1, "in_progress"), s1(4, "completed")), want: selfPool},
		{name: "this run's own jobs are not counted", env: push, jobs: slices.Concat(self, selJobs(4, selRunID, "queued", selSelfHosted, time.Hour), h(1, "in_progress")), want: selfPool, notCall: fmt.Sprintf("/runs/%d/jobs", selRunID)},
		// One pool full: the other.
		{name: "the hosted pool full", env: push, jobs: hostedFull, want: selfPool, notice: "the hosted pool is full (12 of 12)"},
		{name: "bigdisk full", env: push, jobs: slices.Concat(self, h(11, "in_progress"), s1(4, "in_progress")), want: hosted, notice: "the self-hosted pool is full"},
		// Both full: fewer queued wins, a tie self-hosted.
		{name: "both full, hosted more queued", env: push, jobs: slices.Concat(hostedFull, h(2, "queued"), s1(4, "in_progress"), s2(1, "queued")), want: selfPool},
		{name: "both full, self-hosted more queued", env: push, jobs: slices.Concat(hostedFull, h(1, "queued"), s1(5, "queued"), s2(2, "queued")), want: hosted},
		{name: "both full, a tie", env: push, jobs: slices.Concat(hostedFull, s1(4, "in_progress")), want: selfPool, notice: "both pools full: hosted 0 queued, self-hosted 0 queued"},
		// The limits.
		{name: "CI_HOSTED_SHARE unset is 12", env: vars("HS", ""), jobs: hostedFull, want: selfPool, warning: true, notice: "the hosted pool is full (12 of 12)"},
		{name: "CI_HOSTED_SHARE 3", env: vars("HS", "3"), jobs: slices.Concat(self, h(3, "in_progress")), want: selfPool, notice: "the hosted pool is full (3 of 3)"},
		{name: "CI_SELF_HOSTED_BIGDISK unset", env: vars("C1", ""), jobs: hostedFull, want: hosted, warning: true, noCalls: true},
		{name: "CI_SELF_HOSTED_BIGDISK_DOCKER 0", env: vars("C2", "0"), jobs: hostedFull, want: hosted, warning: true, noCalls: true},
		// Forks, other events and other forges: hosted with no call.
		{name: "a same-repository pull request, hosted full", env: gh("pull_request", prRef, selRepo), jobs: hostedFull, want: selfPool},
		{name: "a fork pull request, hosted full", env: gh("pull_request", prRef, "someone/repo"), jobs: hostedFull, want: hosted, notice: forkNote, noCalls: true},
		{name: "a deleted fork's pull request, hosted full", env: gh("pull_request", prRef, ""), jobs: hostedFull, want: hosted, notice: forkNote, noCalls: true},
		{name: "a fork pull_request_target, hosted full", env: gh("pull_request_target", main, "someone/repo"), jobs: hostedFull, want: hosted, notice: refused, noCalls: true},
		{name: "a same-repository pull_request_target, hosted full", env: gh("pull_request_target", main, selRepo), jobs: hostedFull, want: hosted, notice: refused, noCalls: true},
		{name: "a schedule run, hosted full", env: gh("schedule", main, ""), jobs: hostedFull, want: hosted, notice: refused, noCalls: true},
		{name: "a workflow_dispatch run, hosted full", env: gh("workflow_dispatch", main, ""), jobs: hostedFull, want: hosted, notice: refused, noCalls: true},
		{name: "a push to another branch, hosted full", env: gh("push", "refs/heads/topic", ""), jobs: hostedFull, want: hosted, notice: refused, noCalls: true},
		{name: "a push takes no fork check", env: gh("push", main, "someone/repo"), jobs: hostedFull, want: selfPool},
		{name: "off github.com, hosted full", env: selEnv{server: "https://gitea.example", event: "push", ref: main}, jobs: hostedFull, want: hosted, noCalls: true},
		// v1.62 overflow: in a public repository a self-hosted job queued past
		// WAIT_LIMIT (600s) sends the run hosted while hosted has a free slot.
		// Without the wait each of these picks self-hosted (a use tie).
		{name: "a bigdisk job queued 700s, hosted free", env: push, jobs: slices.Concat(self, h(3, "in_progress"), selJobs(1, 8, "queued", selSelfHosted, 700*time.Second)), want: hosted, notice: "overflow:"},
		{name: "a bigdisk-docker job queued 700s, hosted free", env: push, jobs: slices.Concat(self, h(3, "in_progress"), selJobs(1, 8, "queued", selDocker, 700*time.Second)), want: hosted, notice: "overflow:"},
		{name: "a private repository does not overflow", env: private, jobs: slices.Concat(self, h(3, "in_progress"), selJobs(1, 8, "queued", selSelfHosted, 700*time.Second)), want: selfPool, notice: "use hosted 3/12, bigdisk 1/4"},
		{name: "a 500s wait does not overflow", env: push, jobs: slices.Concat(self, h(3, "in_progress"), selJobs(1, 8, "queued", selSelfHosted, 500*time.Second)), want: selfPool, notice: "use hosted 3/12, bigdisk 1/4"},
		{name: "a queued job of this run does not overflow", env: push, jobs: slices.Concat(self, h(1, "in_progress"), selJobs(2, selRunID, "queued", selDocker, time.Hour)), want: selfPool, notice: "use hosted 1/12, bigdisk 0/4, bigdisk-docker 0/4"},
		// The listing.
		{name: "a second jobs page read in full", env: push, jobs: paged, want: selfPool, notice: "the hosted pool is full (12 of 12)"},
		{name: "a failed second jobs page", env: push, jobs: paged,
			break_: func(r map[string]selReply) { r[jobsURL(9, 2)] = selReply{code: 502, body: `{"message":"Bad Gateway"}`} },
			want:   hosted, warning: true},
		// v1.59: a list short of its total_count is a lower bound, named in a
		// ::notice, and the choice still uses it.
		{name: "a jobs list short of its total_count, hosted full", env: push, jobs: hostedFull,
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: strings.Replace(r[jobsURL(7, 1)].body, `"total_count":12`, `"total_count":13`, 1)}
				r[jobsURL(7, 2)] = selReply{code: 200, body: `{"total_count":13,"jobs":[]}`}
			},
			want: selfPool, notice: "12 of 13 entries"},
		{name: "a run list reply that is not 200", env: push, jobs: hostedFull,
			break_: func(r map[string]selReply) {
				r[runsURL("in_progress", 1)] = selReply{code: 403, body: `{"message":"Forbidden"}`}
			},
			want: hosted, warning: true},
		{name: "a run list with no total_count", env: push, jobs: hostedFull,
			break_: func(r map[string]selReply) {
				r[runsURL("queued", 1)] = selReply{code: 200, body: `{"workflow_runs":[]}`}
			},
			want: hosted, warning: true},
		{name: "curl fails", env: push, jobs: hostedFull,
			break_: func(r map[string]selReply) { r[jobsURL(7, 1)] = selReply{exit: 28} },
			want:   hosted, warning: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			replies := selFixture(c.jobs)
			if c.break_ != nil {
				c.break_(replies)
			}
			res := runSel(t, script, replies, c.env)
			if res.rc != 0 {
				t.Fatalf("the step exited %d:\n%s", res.rc, res.stdout)
			}
			wantRunner, wantDocker := selHosted, selHosted
			if c.want == selfPool {
				wantRunner, wantDocker = selOverflow, selOverDock
			}
			if res.runner != wantRunner || res.runnerDocker != wantDocker || res.outputEntries != 2 {
				t.Fatalf("outputs runner=%s runner_docker=%s (%d entries); want runner=%s runner_docker=%s\n%s",
					res.runner, res.runnerDocker, res.outputEntries, wantRunner, wantDocker, res.stdout)
			}
			if has := strings.Contains(res.stdout, "::warning::"); has != c.warning {
				t.Errorf("a ::warning printed: %v, want %v\n%s", has, c.warning, res.stdout)
			}
			if c.notice != "" && !slices.ContainsFunc(strings.Split(res.stdout, "\n"), func(l string) bool {
				return strings.HasPrefix(l, "::notice::") && strings.Contains(l, c.notice)
			}) {
				t.Errorf("want a ::notice containing %q\n%s", c.notice, res.stdout)
			}
			if c.noCalls && len(res.calls) != 0 {
				t.Errorf("the step called the API: %v", res.calls)
			}
			if !c.noCalls && len(res.calls) == 0 {
				t.Errorf("the step made no API call\n%s", res.stdout)
			}
			for _, u := range res.calls {
				if !strings.HasPrefix(u, selAPI+"/") {
					t.Errorf("the step called %q, outside %s", u, selAPI)
				}
				if c.notCall != "" && strings.Contains(u, c.notCall) {
					t.Errorf("the step called %q", u)
				}
			}
		})
	}
}
