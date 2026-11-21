package arch

// Behavioural tests of ci.yml's runner selection (ci-template v1.48, Tenant
// Agent rulings 1024 and 1031, #2128; Codex P1 on #2129). The run: script of
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
type selEnv struct {
	server, headRepo string
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
		"LIMIT=" + selEnvValue(t, "HOSTED_JOBS_PER_REPO"),
		"GRACE=" + selEnvValue(t, "HOSTED_QUEUE_GRACE_SECONDS"),
		"REPO=" + selRepo,
		"HEAD_REPO=" + e.headRepo,
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

// selEnvValue is the workflow-level env value of key in ci.yml.
func selEnvValue(t *testing.T, key string) string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(readCI(t), &doc); err != nil || len(doc.Content) == 0 {
		t.Fatalf("ci.yml does not parse: %s", errString(err))
	}
	v := mapValue(mapValue(doc.Content[0], "env"), key)
	if v == nil {
		t.Fatalf("ci.yml has no env %s", key)
	}
	return v.Value
}

// TestRunnerSelectionStepEnv pins the env the step reads to the env this
// test sets, so a new input of the script is not left at its zero value.
func TestRunnerSelectionStepEnv(t *testing.T) {
	got := readSelStep(t, readCI(t)).env
	sort.Strings(got)
	want := []string{"API", "GRACE", "HEAD_REPO", "JOB_TOKEN", "LIMIT", "REPO", "RUN_ID", "SERVER"}
	if !slices.Equal(got, want) {
		t.Fatalf("the selection step's env keys are %v; this test sets %v", got, want)
	}
	if l, g := selEnvValue(t, "HOSTED_JOBS_PER_REPO"), selEnvValue(t, "HOSTED_QUEUE_GRACE_SECONDS"); l != "12" || g != "60" {
		t.Fatalf("HOSTED_JOBS_PER_REPO=%s HOSTED_QUEUE_GRACE_SECONDS=%s; the cases below assume 12 and 60", l, g)
	}
}

// TestRunnerSelectionScript runs the real selection script against each
// fixture and checks the runner it picks.
func TestRunnerSelectionScript(t *testing.T) {
	script := readSelStep(t, readCI(t)).run
	const (
		hosted   = "hosted"
		overflow = "overflow"
	)
	self := selJobs(1, selRunID, "in_progress", selUbuntu, 5*time.Second) // this preflight job
	gh := selEnv{server: "https://github.com"}
	sameRepoPR := selEnv{server: "https://github.com", headRepo: selRepo}
	forkPR := selEnv{server: "https://github.com", headRepo: "someone/repo"}
	saturated := slices.Concat(self, selJobs(30, 7, "in_progress", selUbuntu, time.Minute), selJobs(5, 8, "queued", selUbuntu, 10*time.Minute))
	// 150 jobs of one run: the first page all done, the 12 in progress on
	// the second page, so only a complete read overflows.
	paged := slices.Concat(selJobs(100, 9, "completed", selUbuntu, time.Hour), selJobs(38, 9, "completed", selUbuntu, time.Hour), selJobs(12, 9, "in_progress", selUbuntu, time.Minute))
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
		warning bool // a ::warning names why there is no count
		noCalls bool // the step must not call the API
	}{
		{name: "no other jobs", env: gh, jobs: self, want: hosted},
		{name: "11 hosted jobs in progress, under the limit", env: gh,
			jobs: slices.Concat(self, selJobs(10, 7, "in_progress", selUbuntu, time.Minute)), want: hosted},
		{name: "12 hosted jobs in progress, at the limit", env: gh,
			jobs: slices.Concat(self, selJobs(11, 7, "in_progress", selUbuntu, time.Minute)), want: overflow},
		{name: "12 hosted jobs in progress across runs", env: gh,
			jobs: slices.Concat(self, selJobs(4, 7, "in_progress", selUbuntu, time.Minute), selJobs(7, 8, "in_progress", selUbuntu, time.Minute)), want: overflow},
		{name: "self-hosted jobs in progress do not count", env: gh,
			jobs: slices.Concat(self, selJobs(10, 7, "in_progress", selUbuntu, time.Minute), selJobs(20, 7, "in_progress", selSelfHosted, time.Minute)), want: hosted},
		{name: "completed jobs do not count", env: gh,
			jobs: slices.Concat(self, selJobs(10, 7, "in_progress", selUbuntu, time.Minute), selJobs(20, 7, "completed", selUbuntu, time.Minute)), want: hosted},
		{name: "12 hosted jobs of another run queued under 60s", env: gh,
			jobs: slices.Concat(self, selJobs(12, 7, "queued", selUbuntu, 45*time.Second)), want: hosted},
		{name: "12 hosted jobs of another run queued 60s", env: gh,
			jobs: slices.Concat(self, selJobs(12, 7, "queued", selUbuntu, 60*time.Second)), want: overflow},
		{name: "one hosted job of another run queued 90s", env: gh,
			jobs: slices.Concat(self, selJobs(1, 7, "queued", selUbuntu, 90*time.Second)), want: overflow},
		{name: "this run's own jobs queued 90s do not count", env: gh,
			jobs: slices.Concat(self, selJobs(12, selRunID, "queued", selUbuntu, 90*time.Second)), want: hosted},
		{name: "a self-hosted job queued 90s does not count", env: gh,
			jobs: slices.Concat(self, selJobs(3, 7, "queued", selSelfHosted, 90*time.Second)), want: hosted},
		{name: "a same-repository pull request at saturation", env: sameRepoPR, jobs: saturated, want: overflow},
		{name: "a fork pull request at saturation", env: forkPR, jobs: saturated, want: hosted, noCalls: true},
		{name: "off github.com at saturation", env: selEnv{server: "https://gitea.example"}, jobs: saturated, want: hosted, noCalls: true},
		{name: "a second jobs page read in full", env: gh, jobs: slices.Concat(self, paged), want: overflow},
		{name: "a failed second jobs page at saturation", env: gh, jobs: slices.Concat(saturated, paged),
			break_: func(r map[string]selReply) { r[jobsURL(9, 2)] = selReply{code: 502, body: `{"message":"Bad Gateway"}`} },
			want:   hosted, warning: true},
		// v1.50: a list short of its total_count is a lower bound, so it
		// still overflows at saturation.
		{name: "a jobs list short of its total_count at saturation", env: gh, jobs: saturated,
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: strings.Replace(r[jobsURL(7, 1)].body, `"total_count":30`, `"total_count":31`, 1)}
				r[jobsURL(7, 2)] = selReply{code: 200, body: `{"total_count":31,"jobs":[]}`}
			},
			want: overflow},
		// v1.50: a short list that reaches no trigger stays hosted with a
		// ::warning naming the shortfall.
		{name: "a jobs list short of its total_count under the limit", env: gh,
			jobs: slices.Concat(self, selJobs(10, 7, "in_progress", selUbuntu, time.Minute)),
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: strings.Replace(r[jobsURL(7, 1)].body, `"total_count":10`, `"total_count":11`, 1)}
				r[jobsURL(7, 2)] = selReply{code: 200, body: `{"total_count":11,"jobs":[]}`}
			},
			want: hosted, warning: true},
		// v1.50: the Actions API lists at most 1000 entries, so a total_count
		// over 1000 is no lower bound the short-list path may trust: it keeps
		// the hosted default, as before v1.50, even with an early empty page.
		{name: "a jobs list with a total_count over 1000 and an early empty page at saturation", env: gh, jobs: saturated,
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: strings.Replace(r[jobsURL(7, 1)].body, `"total_count":30`, `"total_count":1001`, 1)}
				r[jobsURL(7, 2)] = selReply{code: 200, body: `{"total_count":1001,"jobs":[]}`}
			},
			want: hosted, warning: true},
		{name: "a run list reply that is not 200 at saturation", env: gh, jobs: saturated,
			break_: func(r map[string]selReply) {
				r[runsURL("in_progress", 1)] = selReply{code: 403, body: `{"message":"Forbidden"}`}
			},
			want: hosted, warning: true},
		{name: "a run list with no total_count at saturation", env: gh, jobs: saturated,
			break_: func(r map[string]selReply) {
				r[runsURL("queued", 1)] = selReply{code: 200, body: `{"workflow_runs":[]}`}
			},
			want: hosted, warning: true},
		{name: "curl fails at saturation", env: gh, jobs: saturated,
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
			if c.want == overflow {
				wantRunner, wantDocker = selOverflow, selOverDock
			}
			if res.runner != wantRunner || res.runnerDocker != wantDocker || res.outputEntries != 2 {
				t.Fatalf("outputs runner=%s runner_docker=%s (%d entries); want runner=%s runner_docker=%s\n%s",
					res.runner, res.runnerDocker, res.outputEntries, wantRunner, wantDocker, res.stdout)
			}
			if has := strings.Contains(res.stdout, "::warning::"); has != c.warning {
				t.Errorf("a ::warning printed: %v, want %v\n%s", has, c.warning, res.stdout)
			}
			if has := strings.Contains(res.stdout, "::notice::"); has != (c.want == overflow) {
				t.Errorf("the overflow ::notice printed: %v, want %v\n%s", has, c.want == overflow, res.stdout)
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
			}
		})
	}
}
