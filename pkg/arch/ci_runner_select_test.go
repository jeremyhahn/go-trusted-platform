package arch

// Behavioural tests of ci.yml's runner selection (ci-template v1.48, Tenant
// Agent rulings 1024 and 1031, #2128; Codex P1 on #2129; v1.54, the balanced
// runner pool of ruling 1137, whose cases port the template's
// testdata/runner-select-tests.py, absent here). The run: script of
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
	selSelf     = `["self-hosted","linux","x64","bigdisk"]`
	selSelfDock = `["self-hosted","linux","x64","bigdisk-docker"]`
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
type selEnv struct {
	server, event, headRepo string
	hs, c1, c2              string
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
		"HS=" + e.hs,
		"C1=" + e.c1,
		"C2=" + e.c2,
		"REPO=" + selRepo,
		"HEAD_REPO=" + e.headRepo,
		"EVENT=" + e.event,
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
// TestRunnerSelectionStepEnv pins the env the step reads to the env this
// test sets, so a new input of the script is not left at its zero value.
func TestRunnerSelectionStepEnv(t *testing.T) {
	got := readSelStep(t, readCI(t)).env
	sort.Strings(got)
	want := []string{"API", "C1", "C2", "EVENT", "HEAD_REPO", "HS", "JOB_TOKEN", "REPO", "RUN_ID", "SERVER"}
	if !slices.Equal(got, want) {
		t.Fatalf("the selection step's env keys are %v; this test sets %v", got, want)
	}
}

// TestRunnerSelectionScript runs the real selection script against each
// fixture and checks the runner it picks.
func TestRunnerSelectionScript(t *testing.T) {
	script := readSelStep(t, readCI(t)).run
	const (
		hosted     = "hosted"
		selfHosted = "selfHosted"
	)
	self := selJobs(1, selRunID, "in_progress", selUbuntu, 5*time.Second) // this preflight job
	// bal is a push on github.com with the limits CI_HOSTED_SHARE=hs,
	// CI_SELF_HOSTED_BIGDISK=c1 and CI_SELF_HOSTED_BIGDISK_DOCKER=c2.
	bal := func(hs, c1, c2 string) selEnv {
		return selEnv{server: "https://github.com", event: "push", hs: hs, c1: c1, c2: c2}
	}
	gh := bal("10", "10", "10")
	as := func(e selEnv, event, headRepo string) selEnv {
		e.event, e.headRepo = event, headRepo
		return e
	}
	sameRepoPR := as(gh, "pull_request", selRepo)
	forkPR := as(gh, "pull_request", "someone/repo")
	// v1.52: a deleted fork leaves the head repository empty; it is still
	// not this repository.
	deletedForkPR := as(gh, "pull_request", "")
	forkPRT := as(gh, "pull_request_target", "someone/repo")
	// A push has no pull request head: the fork check does not apply.
	pushForeignHead := as(gh, "push", "someone/repo")
	offGH := gh
	offGH.server = "https://gitea.example"
	offGHUnset := bal("10", "", "")
	offGHUnset.server = "https://gitea.example"
	// in is this run's job plus, in run 7, h hosted, s1 bigdisk and s2
	// bigdisk-docker jobs in progress and hq, s1q and s2q of each queued,
	// and more.
	in := func(h, s1, s2, hq, s1q, s2q int, more ...[]selJob) []selJob {
		return slices.Concat(append([][]selJob{self,
			selJobs(h, 7, "in_progress", selUbuntu, time.Minute),
			selJobs(s1, 7, "in_progress", selSelfHosted, time.Minute),
			selJobs(s2, 7, "in_progress", selDocker, time.Minute),
			selJobs(hq, 7, "queued", selUbuntu, time.Minute),
			selJobs(s1q, 7, "queued", selSelfHosted, time.Minute),
			selJobs(s2q, 7, "queued", selDocker, time.Minute),
		}, more...)...)
	}
	busy := in(9, 0, 0, 0, 0, 0)
	// 30 hosted jobs of run 7: the hosted pool is full, so a complete read
	// goes self-hosted.
	thirty := in(30, 0, 0, 0, 0, 0)
	// 150 jobs of one run: the first page all done, the 12 in progress on
	// the second page, so only a complete read finds the hosted pool full.
	paged := slices.Concat(selJobs(100, 9, "completed", selUbuntu, time.Hour), selJobs(38, 9, "completed", selUbuntu, time.Hour), selJobs(12, 9, "in_progress", selUbuntu, time.Minute))
	jobsURL := func(run, page int) string {
		return selPage(fmt.Sprintf("%s/runs/%d/jobs?filter=latest", selAPI, run), page)
	}
	runsURL := func(st string, page int) string { return selPage(selAPI+"/runs?status="+st, page) }

	type selCase struct {
		name    string
		env     selEnv
		jobs    []selJob
		break_  func(map[string]selReply)
		want    string
		out     []string // substrings the step's stdout holds
		warning bool     // a ::warning names why there is no count
		noCalls bool     // the step must not call the API
	}
	cases := []selCase{
		{name: "hosted use below bigdisk use", env: gh, jobs: in(2, 5, 0, 0, 0, 0), want: hosted,
			out: []string{"hosted 2 of CI_HOSTED_SHARE=10", "bigdisk 5 of CI_SELF_HOSTED_BIGDISK=10"}},
		{name: "self-hosted use below hosted use", env: gh, jobs: in(5, 2, 2, 0, 0, 0), want: selfHosted},
		{name: "bigdisk-docker use equal to hosted use", env: gh, jobs: in(3, 0, 3, 0, 0, 0), want: hosted,
			out: []string{"use hosted 3/10, bigdisk 0/10, bigdisk-docker 3/10"}},
		{name: "a tie across limits goes hosted", env: bal("10", "20", "10"), jobs: in(2, 4, 0, 0, 0, 0), want: hosted},
		{name: "bigdisk-docker use above hosted use across limits", env: bal("20", "10", "6"), jobs: in(4, 0, 3, 0, 0, 0), want: hosted},
		{name: "both self-hosted kinds below hosted use across limits", env: bal("20", "6", "6"), jobs: in(9, 1, 1, 0, 0, 0), want: selfHosted},
		{name: "one each is a tie", env: gh, jobs: in(1, 1, 0, 0, 0, 0), want: hosted},
		{name: "nothing in flight", env: gh, jobs: self, want: hosted, out: []string{"hosted 0 of"}},
		{name: "queued jobs count", env: gh, jobs: in(1, 1, 0, 3, 1, 1), want: selfHosted,
			out: []string{"hosted 4 of", "(3 queued)", "(2 self-hosted queued)"}},
		{name: "completed, unlabelled and other self-hosted jobs do not count", env: gh,
			jobs: in(1, 0, 0, 0, 0, 0, selJobs(30, 7, "completed", selDocker, time.Minute), selJobs(5, 7, "in_progress", nil, time.Minute),
				selJobs(1, 7, "in_progress", []string{"self-hosted", "linux", "x64", "release"}, time.Minute)),
			want: selfHosted, out: []string{"bigdisk 0 of"}},
		{name: "a job labelled bigdisk and bigdisk-docker is bigdisk-docker", env: gh,
			jobs: in(5, 0, 0, 0, 0, 0, selJobs(1, 7, "in_progress", []string{"self-hosted", "bigdisk", "bigdisk-docker"}, time.Minute)),
			want: selfHosted, out: []string{"bigdisk 0 of", "bigdisk-docker 1 of"}},
		{name: "this run's jobs do not count", env: gh,
			jobs: in(1, 0, 0, 0, 0, 0, selJobs(50, selRunID, "in_progress", selDocker, time.Minute)),
			want: selfHosted, out: []string{"bigdisk-docker 0 of"}},
		{name: "a second jobs page read in full", env: gh, jobs: slices.Concat(self, paged), want: selfHosted,
			out: []string{"the hosted pool is full (12 of 10)"}},
		{name: "the hosted pool full", env: gh, jobs: in(10, 9, 9, 0, 0, 0), want: selfHosted,
			out: []string{"the hosted pool is full (10 of 10)"}},
		{name: "the self-hosted pool full", env: gh, jobs: in(9, 10, 10, 0, 0, 0), want: hosted,
			out: []string{"the self-hosted pool is full"}},
		{name: "bigdisk alone full", env: bal("10", "2", "10"), jobs: in(9, 2, 0, 0, 0, 0), want: hosted,
			out: []string{"bigdisk 2 of 2, bigdisk-docker 0 of 10"}},
		{name: "both pools full, fewer queued self-hosted", env: gh, jobs: in(6, 9, 0, 4, 1, 0), want: selfHosted,
			out: []string{"both pools full: hosted 4 queued, self-hosted 1 queued"}},
		{name: "both pools full, fewer queued hosted", env: gh, jobs: in(10, 5, 8, 1, 0, 2), want: hosted},
		{name: "both pools full, a queued tie", env: gh, jobs: in(12, 12, 0, 0, 0, 0), want: hosted,
			out: []string{"hosted 0 queued, self-hosted 0 queued"}},
		{name: "a leading zero limit", env: bal("10", "08", "10"), jobs: in(5, 1, 0, 0, 0, 0), want: selfHosted,
			out: []string{"CI_SELF_HOSTED_BIGDISK=8"}},
		{name: "a fork pull request", env: forkPR, jobs: busy, want: hosted, noCalls: true},
		{name: "a deleted-fork pull request", env: deletedForkPR, jobs: busy, want: hosted, noCalls: true},
		{name: "a fork pull_request_target", env: forkPRT, jobs: busy, want: hosted, noCalls: true},
		{name: "a same-repository pull request", env: sameRepoPR, jobs: busy, want: selfHosted},
		{name: "a push takes no fork check", env: pushForeignHead, jobs: busy, want: selfHosted},
		{name: "off github.com", env: offGH, jobs: busy, want: hosted, noCalls: true},
		{name: "off github.com with no self-hosted limits", env: offGHUnset, jobs: busy, want: hosted, noCalls: true},
		{name: "a failed second jobs page", env: gh, jobs: slices.Concat(thirty, paged),
			break_: func(r map[string]selReply) { r[jobsURL(9, 2)] = selReply{code: 502, body: `{"message":"Bad Gateway"}`} },
			want:   hosted, warning: true},
		// v1.54: a list short of its total_count is no lower bound (v1.50 is
		// replaced): the run stays hosted.
		{name: "a jobs list short of its total_count", env: gh, jobs: thirty,
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: strings.Replace(r[jobsURL(7, 1)].body, `"total_count":30`, `"total_count":31`, 1)}
				r[jobsURL(7, 2)] = selReply{code: 200, body: `{"total_count":31,"jobs":[]}`}
			},
			want: hosted, warning: true, out: []string{"30 of 31 entries"}},
		{name: "a jobs page that cannot be counted", env: gh, jobs: thirty,
			break_: func(r map[string]selReply) {
				r[jobsURL(7, 1)] = selReply{code: 200, body: `{"total_count":1,"jobs":[7]}`}
			},
			want: hosted, warning: true, out: []string{"could not be counted"}},
		{name: "a run list reply that is not 200", env: gh, jobs: thirty,
			break_: func(r map[string]selReply) {
				r[runsURL("in_progress", 1)] = selReply{code: 403, body: `{"message":"Forbidden"}`}
			},
			want: hosted, warning: true},
		{name: "a run list with no total_count", env: gh, jobs: thirty,
			break_: func(r map[string]selReply) {
				r[runsURL("queued", 1)] = selReply{code: 200, body: `{"workflow_runs":[]}`}
			},
			want: hosted, warning: true},
		{name: "curl fails", env: gh, jobs: thirty,
			break_: func(r map[string]selReply) { r[jobsURL(7, 1)] = selReply{exit: 28} },
			want:   hosted, warning: true},
	}
	for _, v := range []string{"", "0", "ten", "-3", "00", "1.5"} {
		cases = append(cases,
			selCase{name: "CI_SELF_HOSTED_BIGDISK=" + v, env: bal("10", v, "10"), jobs: busy, want: hosted, warning: true, noCalls: true,
				out: []string{"CI_SELF_HOSTED_BIGDISK='" + v + "'"}},
			selCase{name: "CI_SELF_HOSTED_BIGDISK_DOCKER=" + v, env: bal("10", "10", v), jobs: busy, want: hosted, warning: true, noCalls: true,
				out: []string{"CI_SELF_HOSTED_BIGDISK_DOCKER='" + v + "'"}})
	}
	for _, v := range []string{"", "0", "x12"} {
		cases = append(cases, selCase{name: "CI_HOSTED_SHARE=" + v, env: bal(v, "10", "10"), jobs: in(11, 1, 0, 0, 0, 0),
			want: selfHosted, warning: true, out: []string{"HS=12", "hosted 11 of CI_HOSTED_SHARE=12"}})
	}
	cases = append(cases, selCase{name: "CI_HOSTED_SHARE unset, the hosted pool full", env: bal("", "10", "10"), jobs: in(12, 9, 0, 0, 0, 0),
		want: selfHosted, warning: true, out: []string{"the hosted pool is full (12 of 12)"}})

	const selfNotice = "this run's jobs run on the self-hosted runners (bigdisk, bigdisk-docker)"
	ownJobs := fmt.Sprintf("/runs/%d/jobs", selRunID)
	for _, c := range cases {
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
			if c.want == selfHosted {
				wantRunner, wantDocker = selSelf, selSelfDock
			}
			if res.runner != wantRunner || res.runnerDocker != wantDocker || res.outputEntries != 2 {
				t.Fatalf("outputs runner=%s runner_docker=%s (%d entries); want runner=%s runner_docker=%s\n%s",
					res.runner, res.runnerDocker, res.outputEntries, wantRunner, wantDocker, res.stdout)
			}
			if has := strings.Contains(res.stdout, "::warning::"); has != c.warning {
				t.Errorf("a ::warning printed: %v, want %v\n%s", has, c.warning, res.stdout)
			}
			for _, o := range c.out {
				if !strings.Contains(res.stdout, o) {
					t.Errorf("the step's output lacks %q\n%s", o, res.stdout)
				}
			}
			// v1.52 prints a ::notice for a fork pull request (an empty head
			// repository is one too).
			const forkNotice = "::notice::runner selection: this pull request's head repository is not this repository (a fork)"
			wantFork := (c.env.event == "pull_request" || c.env.event == "pull_request_target") && c.env.headRepo != selRepo
			if has := strings.Contains(res.stdout, forkNotice); has != wantFork {
				t.Errorf("the fork ::notice printed: %v, want %v\n%s", has, wantFork, res.stdout)
			}
			if has := strings.Contains(res.stdout, selfNotice); has != (c.want == selfHosted) {
				t.Errorf("the self-hosted ::notice printed: %v, want %v\n%s", has, c.want == selfHosted, res.stdout)
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
				if strings.Contains(u, ownJobs) {
					t.Errorf("the step read this run's own jobs: %q", u)
				}
			}
		})
	}
}
