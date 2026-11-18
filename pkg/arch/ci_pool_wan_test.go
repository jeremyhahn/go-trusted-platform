package arch

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 862: a pool host's downloads cross the owner's WAN unless they come
// from the LAN. Every pool sets GOPROXY with the LAN module proxy first, so a
// workflow step that can run on the pool (its job may run self-hosted and its
// if: does not keep it to github-hosted) keeps that proxy and fetches no build
// artifact or cache from GitHub's storage.

// poolHostedOnly is the if: term that keeps a step off the pool.
const poolHostedOnly = "runner.environment == 'github-hosted'"

// poolOffGitHub is the if: term of a step that runs only on Gitea, whose
// artifacts are served on the LAN.
const poolOffGitHub = "github.server_url != 'https://github.com'"

// poolWANActions download from GitHub's artifact and cache storage.
var poolWANActions = []string{"actions/download-artifact@", "actions/cache@", "actions/cache/restore@"}

type poolStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

// Ruling 869 (pending InfoSec's review of M-8): with the LAN-first proxy,
// integrity rests on the checksum database. A pool job that runs Go natively
// (a setup-go step that can run on the pool) sets -mod=readonly in its job
// GOFLAGS and runs scripts/ci-go-integrity.sh as the step right after
// setup-go, under the same if:; no step relaxes either.
const poolIntegrityScript = "scripts/ci-go-integrity.sh"

// poolSumdbEnv are the variables that exempt modules from the checksum
// database or replace it.
var poolSumdbEnv = []string{"GOSUMDB", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "GOPRIVATE"}

func poolReadonly(flags string) bool {
	return strings.Contains(" "+flags+" ", " -mod=readonly ") && !strings.Contains(" "+flags, " -insecure")
}

func poolIntegrityProblems(file, where string, wf poolWorkflow, job poolJob) []string {
	setup := -1
	for i, s := range job.Steps {
		if strings.HasPrefix(s.Uses, "actions/setup-go@") && !strings.Contains(s.If, poolHostedOnly) {
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
		problems = append(problems, where+": runs Go on the pool without -mod=readonly (and no -insecure) in its job GOFLAGS (ruling 869)")
	}
	if setup+1 >= len(job.Steps) || strings.TrimSpace(job.Steps[setup+1].Run) != poolIntegrityScript ||
		job.Steps[setup+1].If != job.Steps[setup].If {
		problems = append(problems, where+": the step after setup-go is not `"+poolIntegrityScript+"` under setup-go's if: (ruling 869)")
	}
	for _, s := range job.Steps {
		for _, v := range poolSumdbEnv {
			if _, set := s.Env[v]; set {
				problems = append(problems, where+" step "+s.Name+": sets "+v+", which relaxes the checksum database (ruling 869)")
			}
		}
		if f, set := s.Env["GOFLAGS"]; set && !poolReadonly(f) {
			problems = append(problems, where+" step "+s.Name+": sets GOFLAGS without -mod=readonly or with -insecure (ruling 869)")
		}
	}
	return problems
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

// poolWANProblems lists every step of a self-hosted-capable job that can
// reach the WAN in one of the ways ruling 862 forbids.
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
		if _, ok := wf.Env["GOPROXY"]; ok {
			problems = append(problems, file+": the workflow env sets GOPROXY, replacing the pool's LAN-first module proxy")
		}
		problems = append(problems, poolIntegrityProblems(file, where, wf, job)...)
		if _, ok := job.Env["GOPROXY"]; ok {
			problems = append(problems, where+": the job env sets GOPROXY, replacing the pool's LAN-first module proxy")
		}
		for _, s := range job.Steps {
			// A step kept to github-hosted never runs on the pool, and one kept
			// off github.com never fetches from GitHub's storage.
			if strings.Contains(s.If, poolHostedOnly) || strings.Contains(s.If, poolOffGitHub) {
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
	for _, c := range []struct {
		name, body, want string
	}{
		{"a pool step sets GOPROXY", "jobs:\n  a:\n" + pool + "    steps:\n      - name: s\n        env:\n          GOPROXY: https://proxy.golang.org\n", "step s: sets GOPROXY"},
		{"a pool step downloads an artifact", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        uses: actions/download-artifact@0000\n", "uses actions/download-artifact@"},
		{"a pool step restores a cache", "jobs:\n  a:\n" + pool + "    steps:\n      - name: c\n        uses: actions/cache/restore@0000\n", "uses actions/cache/restore@"},
		{"a pool job sets GOPROXY", "jobs:\n  a:\n" + pool + "    env:\n      GOPROXY: https://proxy.golang.org\n    steps: []\n", "the job env sets GOPROXY"},
		{"an expression that can reach the pool", "jobs:\n  a:\n    runs-on: ${{ cond && fromJSON('[\"self-hosted\",\"bigdisk\"]') || 'ubuntu-latest' }}\n    steps:\n      - name: s\n        env:\n          GOPROXY: x\n", "step s: sets GOPROXY"},
		{"unparsable", "jobs: [", "not parseable"},
		{"native Go without read-only modules", "jobs:\n  a:\n" + pool + "    steps:\n      - uses: actions/setup-go@0\n      - run: scripts/ci-go-integrity.sh\n", "without -mod=readonly"},
		{"native Go without the integrity step", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly\n    steps:\n      - uses: actions/setup-go@0\n      - run: go test ./...\n", "the step after setup-go is not"},
		{"the integrity step under another if", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly\n    steps:\n      - uses: actions/setup-go@0\n        if: x\n      - run: scripts/ci-go-integrity.sh\n", "the step after setup-go is not"},
		{"a step exempts modules", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly\n    steps:\n      - uses: actions/setup-go@0\n      - run: scripts/ci-go-integrity.sh\n      - name: t\n        env:\n          GONOSUMDB: github.com/x\n", "sets GONOSUMDB"},
		{"a step drops read-only modules", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly\n    steps:\n      - uses: actions/setup-go@0\n      - run: scripts/ci-go-integrity.sh\n      - name: t\n        env:\n          GOFLAGS: -mod=mod\n", "sets GOFLAGS without -mod=readonly"},
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
		{"native Go with read-only modules and the integrity step", "jobs:\n  a:\n" + pool + "    env:\n      GOFLAGS: -mod=readonly\n    steps:\n      - uses: actions/setup-go@0\n        if: c\n      - if: c\n        run: scripts/ci-go-integrity.sh\n      - run: go test ./...\n"},
		{"a Gitea-only step of a pool job may download", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: github.server_url != 'https://github.com'\n        uses: actions/download-artifact@0000\n"},
		{"a hosted-only step of a pool job may download", "jobs:\n  a:\n" + pool + "    steps:\n      - name: d\n        if: runner.environment == 'github-hosted'\n        uses: actions/download-artifact@0000\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if p := poolWANProblems("f.yml", []byte(c.body)); len(p) != 0 {
				t.Fatalf("want no problem, got %v", p)
			}
		})
	}
}
