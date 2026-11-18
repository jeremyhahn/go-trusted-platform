package arch

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 862: a pool host's downloads cross the owner's WAN unless they come
// from the LAN. Every pool sets GOPROXY with the LAN module proxy first, so a
// workflow step that can run on the pool keeps that proxy and fetches no
// build artifact or cache from GitHub's storage.
//
// Ruling 869 (pending InfoSec's review of M-8): with the LAN-first proxy,
// integrity rests on the checksum database. A pool job that runs Go natively
// (a setup-go step that can run on the pool) sets -mod=readonly in its job
// GOFLAGS, and every later step of it that can run on the pool and runs go or
// make calls scripts/ci-go-integrity.sh as its first command, so no Go runs
// unless the gate passed in that same step. No step relaxes either.

const (
	// poolHostedTerm keeps a step off the pool when it is a top-level
	// conjunct of the step's if: (and the if: has no ||).
	poolHostedTerm = "runner.environment == 'github-hosted'"
	// poolGiteaTerm keeps a step off github.com the same way; its
	// artifacts are served by Gitea on the LAN.
	poolGiteaTerm = "github.server_url != 'https://github.com'"
	// poolIntegrityScript is the gate every pool Go step calls first.
	poolIntegrityScript = "scripts/ci-go-integrity.sh"
)

// poolWANActions download from GitHub's artifact and cache storage.
var poolWANActions = []string{"actions/download-artifact@", "actions/cache@", "actions/cache/restore@"}

// poolSumdbEnv are the variables that exempt modules from the checksum
// database or the proxy, or replace the database.
var poolSumdbEnv = []string{"GOSUMDB", "GONOSUMDB", "GONOSUMCHECK", "GONOPROXY", "GOINSECURE", "GOPRIVATE"}

// poolGoRun matches a script that runs go or make as a command.
var poolGoRun = regexp.MustCompile(`(^|[\s;&|(` + "`" + `])(go|make)\s`)

type poolStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

type poolJob struct {
	RunsOn yaml.Node         `yaml:"runs-on"`
	Env    map[string]string `yaml:"env"`
	Steps  []poolStep        `yaml:"steps"`
}

type poolWorkflow struct {
	Env  map[string]string  `yaml:"env"`
	Jobs map[string]poolJob `yaml:"jobs"`
}

// poolConjunct reports whether term is a top-level conjunct of the if:
// expression cond, which must hold no ||: only then does the term alone
// decide that the step is skipped when the term is false.
func poolConjunct(cond, term string) bool {
	c := strings.TrimSpace(cond)
	c = strings.TrimSuffix(strings.TrimPrefix(c, "${{"), "}}")
	if strings.Contains(c, "||") {
		return false
	}
	for _, part := range strings.Split(c, "&&") {
		if strings.Trim(strings.TrimSpace(part), "() ") == term {
			return true
		}
	}
	return false
}

func poolOff(s poolStep) bool {
	return poolConjunct(s.If, poolHostedTerm) || poolConjunct(s.If, poolGiteaTerm)
}

// poolMayRun reports whether a runs-on can name a self-hosted runner.
func poolMayRun(n yaml.Node) bool {
	var b strings.Builder
	var walk func(*yaml.Node)
	walk = func(x *yaml.Node) {
		b.WriteString(x.Value + " ")
		for _, c := range x.Content {
			walk(c)
		}
	}
	walk(&n)
	return strings.Contains(b.String(), "self-hosted")
}

func poolReadonly(flags string) bool {
	ro := false
	for _, f := range strings.Fields(flags) {
		switch {
		case f == "-mod=readonly":
			ro = true
		case f == "-mod" || strings.HasPrefix(f, "-mod=") || f == "-insecure" || strings.HasPrefix(f, "-insecure="):
			return false
		}
	}
	return ro
}

// poolFirstCommand is a script's first command: its first line that is not
// blank, a comment or a `set` of shell options.
func poolFirstCommand(run string) string {
	for _, l := range strings.Split(run, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "set -") {
			continue
		}
		return l
	}
	return ""
}

func poolIntegrityProblems(where string, wf poolWorkflow, job poolJob) []string {
	setup := -1
	for i, s := range job.Steps {
		if strings.HasPrefix(s.Uses, "actions/setup-go@") && !poolOff(s) {
			setup = i
			break
		}
	}
	if setup < 0 {
		return nil
	}
	var problems []string
	flags, ok := job.Env["GOFLAGS"]
	if !ok {
		flags = wf.Env["GOFLAGS"]
	}
	if !poolReadonly(flags) {
		problems = append(problems, where+": runs Go on the pool without -mod=readonly (and no other -mod, no -insecure) in its job GOFLAGS (ruling 869)")
	}
	for i, s := range job.Steps {
		for _, v := range poolSumdbEnv {
			if _, set := s.Env[v]; set {
				problems = append(problems, where+" step "+s.Name+": sets "+v+", which relaxes the checksum database or the proxy (ruling 869)")
			}
		}
		if f, set := s.Env["GOFLAGS"]; set && !poolReadonly(f) {
			problems = append(problems, where+" step "+s.Name+": sets GOFLAGS without -mod=readonly, or with another -mod or -insecure (ruling 869)")
		}
		if i > setup && !poolOff(s) && poolGoRun.MatchString(s.Run) && poolFirstCommand(s.Run) != poolIntegrityScript {
			problems = append(problems, where+" step "+s.Name+": runs go or make on the pool without `"+poolIntegrityScript+"` as its first command (ruling 869)")
		}
	}
	return problems
}

// poolWANProblems lists every step of a self-hosted-capable job that can
// reach the WAN, or run Go, in a way rulings 862 and 869 forbid.
func poolWANProblems(file string, data []byte) []string {
	var wf poolWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return []string{file + ": not parseable YAML: " + err.Error()}
	}
	var problems []string
	names := make([]string, 0, len(wf.Jobs))
	for n := range wf.Jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		job := wf.Jobs[name]
		if !poolMayRun(job.RunsOn) {
			continue
		}
		where := file + ": job " + name
		problems = append(problems, poolIntegrityProblems(where, wf, job)...)
		if _, ok := wf.Env["GOPROXY"]; ok {
			problems = append(problems, file+": the workflow env sets GOPROXY, replacing the pool's LAN-first module proxy")
		}
		if _, ok := job.Env["GOPROXY"]; ok {
			problems = append(problems, where+": the job env sets GOPROXY, replacing the pool's LAN-first module proxy")
		}
		for _, s := range job.Steps {
			if poolOff(s) {
				continue
			}
			step := where + " step " + s.Name
			if _, ok := s.Env["GOPROXY"]; ok {
				problems = append(problems, step+": sets GOPROXY, replacing the pool's LAN-first module proxy with a WAN one")
			}
			for _, a := range poolWANActions {
				if strings.HasPrefix(s.Uses, a) {
					problems = append(problems, step+": uses "+a+", which downloads from GitHub's storage over the WAN")
				}
			}
		}
	}
	return problems
}

func TestCIPoolStepsKeepTheLANProxy(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range poolWANProblems(filepath.Base(f), data) {
			t.Error(p)
		}
	}
}

func TestPoolWANProblems(t *testing.T) {
	const pool = "    runs-on: [self-hosted, linux, x64, bigdisk]\n"
	const ro = "    env:\n      GOFLAGS: -mod=readonly\n"
	const setup = "      - uses: actions/setup-go@0\n"
	gated := func(cmd string) string {
		return "      - name: t\n        run: |\n          " + poolIntegrityScript + "\n          " + cmd + "\n"
	}
	for _, c := range []struct {
		name, body, want string
	}{
		{"a pool step sets GOPROXY", "jobs:\n  a:\n" + pool + "    steps:\n      - name: s\n        env:\n          GOPROXY: https://proxy.golang.org\n", "step s: sets GOPROXY"},
		{"a pool step downloads an artifact", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        uses: actions/download-artifact@0000\n", "uses actions/download-artifact@"},
		{"a pool step restores a cache", "jobs:\n  a:\n" + pool + "    steps:\n      - name: c\n        uses: actions/cache/restore@0000\n", "uses actions/cache/restore@"},
		{"a pool job sets GOPROXY", "jobs:\n  a:\n" + pool + "    env:\n      GOPROXY: https://proxy.golang.org\n    steps: []\n", "the job env sets GOPROXY"},
		{"an expression that can reach the pool", "jobs:\n  a:\n    runs-on: ${{ cond && fromJSON('[\"self-hosted\",\"bigdisk\"]') || 'ubuntu-latest' }}\n    steps:\n      - name: s\n        env:\n          GOPROXY: x\n", "step s: sets GOPROXY"},
		{"a hosted term under || is not hosted-only", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: runner.environment == 'github-hosted' || true\n        uses: actions/download-artifact@0000\n", "uses actions/download-artifact@"},
		{"a negated hosted term is not hosted-only", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: \"!(runner.environment == 'github-hosted')\"\n        uses: actions/download-artifact@0000\n", "uses actions/download-artifact@"},
		{"unparsable", "jobs: [", "not parseable"},
		{"native Go without read-only modules", "jobs:\n  a:\n" + pool + "    steps:\n" + setup + gated("go test ./..."), "without -mod=readonly"},
		{"a later -mod in the job GOFLAGS", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly -mod=mod\n    steps:\n" + setup + gated("go test ./..."), "without -mod=readonly"},
		{"a Go step without the gate first", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        run: go test ./...\n", "step t: runs go or make on the pool without"},
		{"a make step with the gate second", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        run: |\n          make test\n          " + poolIntegrityScript + "\n", "step t: runs go or make on the pool without"},
		{"a step exempts modules", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        env:\n          GONOSUMDB: github.com/x\n", "sets GONOSUMDB"},
		{"a step exempts a module from the proxy", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        env:\n          GONOPROXY: github.com/x\n", "sets GONOPROXY"},
		{"a step drops read-only modules", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        env:\n          GOFLAGS: -mod=mod\n", "sets GOFLAGS without -mod=readonly"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := poolWANProblems("f.yml", []byte(c.body))
			if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Fatalf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
	for _, c := range []struct{ name, body string }{
		{"a hosted job may set GOPROXY", "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: s\n        env:\n          GOPROXY: https://proxy.golang.org\n"},
		{"native Go with read-only modules and the gate first", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + gated("go test ./...") + "      - name: e\n        run: echo done\n"},
		{"a Go step before setup-go needs no gate", "jobs:\n  a:\n" + pool + ro + "    steps:\n      - name: pin\n        run: make -s pin\n" + setup + gated("go test ./...")},
		{"a hosted-only Go step needs no gate", "jobs:\n  a:\n" + pool + ro + "    steps:\n" + setup + "      - name: t\n        if: ${{ !cancelled() && runner.environment == 'github-hosted' }}\n        run: make test\n"},
		{"a Gitea-only step of a pool job may download", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: x && github.server_url != 'https://github.com'\n        uses: actions/download-artifact@0000\n"},
		{"a hosted-only step of a pool job may download", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: runner.environment == 'github-hosted'\n        uses: actions/download-artifact@0000\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if p := poolWANProblems("f.yml", []byte(c.body)); len(p) != 0 {
				t.Fatalf("want no problem, got %v", p)
			}
		})
	}
}
