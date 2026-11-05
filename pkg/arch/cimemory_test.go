package arch

// Guards that every container CI starts has a memory limit (#1178).
//
// Unbounded, two toolchain containers on ci-node-2 held 36.5 GB and 32.4 GB
// and the shared runner host swapped. CI starts containers in three places,
// and each must carry a limit with swap set to the same size (so no swap):
//
//   - scripts/in-toolchain-image.sh, which every toolchain step of ci.yml's
//     image job calls: --memory and --memory-swap from IN_IMAGE_MEMORY, which
//     each such step sets, at 16g or less;
//   - compose.yaml's integration service, which the integration legs and the
//     soak job run through `make integration-test`: mem_limit and
//     memswap_limit from the Makefile's IT_MEMORY, which those jobs set;
//   - the Makefile's run-integration-suite `docker run`.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	// toolchainScript starts every toolchain container of ci.yml.
	toolchainScript = "scripts/in-toolchain-image.sh"

	// devcontainerCompose holds the integration service the legs run.
	devcontainerCompose = "build/docker/devcontainer/compose.yaml"

	// ciMemoryCeilingMiB is the most memory any CI container may be given.
	ciMemoryCeilingMiB = 16 * 1024

	// fakeToolchainDocker records each docker call's arguments, one call per
	// line, and swallows the checkout `docker cp` streams in.
	fakeToolchainDocker = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_CALLS"
if [ "$1" = cp ]; then cat > /dev/null; fi
exit 0
`
)

// memorySizePattern is a docker or compose memory size in MiB or GiB.
var memorySizePattern = regexp.MustCompile(`^([1-9][0-9]*)([mg])$`)

// CIMemoryError is one CI container launch without a valid memory limit.
type CIMemoryError struct {
	// Where names the launch: a ci.yml job and step, or a file.
	Where string
	// Reason says what is missing or wrong.
	Reason string
}

func (e *CIMemoryError) Error() string {
	return "CI memory limit: " + e.Where + ": " + e.Reason
}

type ciMemoryStep struct {
	Name string            `yaml:"name"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type ciMemoryJob struct {
	Env   map[string]string `yaml:"env"`
	Steps []ciMemoryStep    `yaml:"steps"`
}

type ciMemoryWorkflow struct {
	Env  map[string]string      `yaml:"env"`
	Jobs map[string]ciMemoryJob `yaml:"jobs"`
}

// memorySizeMiB parses a size such as 16g or 512m into MiB.
func memorySizeMiB(size string) (int, bool) {
	m := memorySizePattern.FindStringSubmatch(size)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	if m[2] == "g" {
		n *= 1024
	}
	return n, true
}

// memoryLimitFinding reports a missing, malformed or over-ceiling size.
func memoryLimitFinding(where, variable, size string) error {
	if size == "" {
		return &CIMemoryError{Where: where, Reason: "sets no " + variable}
	}
	mib, ok := memorySizeMiB(size)
	if !ok {
		return &CIMemoryError{Where: where, Reason: variable + " " + strconv.Quote(size) + " is not a size in m or g"}
	}
	if mib > ciMemoryCeilingMiB {
		return &CIMemoryError{Where: where, Reason: variable + " " + size + " is above the 16g ceiling"}
	}
	return nil
}

// ciMemoryFindings checks every ci.yml step that starts a CI container: a
// toolchain step must set IN_IMAGE_MEMORY, an integration step IT_MEMORY (on
// the step or its job). It fails closed when no toolchain step is found.
func ciMemoryFindings(wf ciMemoryWorkflow) []error {
	jobIDs := make([]string, 0, len(wf.Jobs))
	for id := range wf.Jobs {
		jobIDs = append(jobIDs, id)
	}
	sort.Strings(jobIDs)

	var findings []error
	toolchainSteps := 0
	for _, id := range jobIDs {
		job := wf.Jobs[id]
		for _, step := range job.Steps {
			where := "job " + id + ", step " + strconv.Quote(step.Name)
			launchesToolchain := strings.Contains(step.Run, toolchainScript)
			launchesIntegration := strings.Contains(step.Run, "make integration-test") || strings.Contains(step.Run, "$SOAK_TARGET")
			if launchesToolchain {
				toolchainSteps++
				if err := memoryLimitFinding(where, "IN_IMAGE_MEMORY", step.Env["IN_IMAGE_MEMORY"]); err != nil {
					findings = append(findings, err)
				}
			}
			if launchesIntegration {
				size := step.Env["IT_MEMORY"]
				if size == "" {
					size = job.Env["IT_MEMORY"]
				}
				if err := memoryLimitFinding(where, "IT_MEMORY", size); err != nil {
					findings = append(findings, err)
				}
			}
			if launchesToolchain || launchesIntegration {
				if err := cgroupParentFinding(where, step, job, wf); err != nil {
					findings = append(findings, err)
				}
			}
		}
	}
	if toolchainSteps == 0 {
		findings = append(findings, &CIMemoryError{Where: ciWorkflowFile, Reason: "no step runs " + toolchainScript})
	}
	return findings
}

// clearedCgroupParentPattern matches a command line that passes an empty
// CI_CGROUP_PARENT, as in `make integration-test CI_CGROUP_PARENT=`.
var clearedCgroupParentPattern = regexp.MustCompile(`(^|\s)CI_CGROUP_PARENT=(''|""|\s|$)`)

// cgroupParentFinding reports a CI launch step that clears CI_CGROUP_PARENT.
// The launchers default it to ci.slice, so a step keeps the parent unless its
// own env, its job's or the workflow's (nearest wins), or its command line,
// sets it empty, and the container would run in system.slice, outside the
// runner host's ci.slice bound.
func cgroupParentFinding(where string, step ciMemoryStep, job ciMemoryJob, wf ciMemoryWorkflow) error {
	for _, env := range []map[string]string{step.Env, job.Env, wf.Env} {
		value, set := env["CI_CGROUP_PARENT"]
		if !set {
			continue
		}
		if value == "" {
			return &CIMemoryError{Where: where, Reason: "sets CI_CGROUP_PARENT empty, so its container has no cgroup parent"}
		}
		break
	}
	if clearedCgroupParentPattern.MatchString(step.Run) {
		return &CIMemoryError{Where: where, Reason: "passes an empty CI_CGROUP_PARENT, so its container has no cgroup parent"}
	}
	return nil
}

// composeMemoryFinding checks that the integration service bounds its memory
// and gives it no swap.
func composeMemoryFinding(memLimit, memswapLimit string) error {
	where := devcontainerCompose + " integration service"
	switch {
	case memLimit == "":
		return &CIMemoryError{Where: where, Reason: "has no mem_limit"}
	case memswapLimit != memLimit:
		return &CIMemoryError{Where: where, Reason: "memswap_limit " + strconv.Quote(memswapLimit) + " differs from mem_limit " + strconv.Quote(memLimit)}
	}
	return nil
}

// composeCgroupParent is the integration service's cgroup_parent: the
// Makefile's CI_CGROUP_PARENT, ci.slice when unset, none when set empty.
const composeCgroupParent = "${CI_CGROUP_PARENT-ci.slice}"

// composeCgroupParentFinding reports a compose integration service whose
// cgroup_parent is missing or does not come from CI_CGROUP_PARENT.
func composeCgroupParentFinding(cgroupParent string) error {
	where := devcontainerCompose + " integration service"
	switch cgroupParent {
	case composeCgroupParent:
		return nil
	case "":
		return &CIMemoryError{Where: where, Reason: "has no cgroup_parent"}
	}
	return &CIMemoryError{Where: where, Reason: "cgroup_parent " + strconv.Quote(cgroupParent) + " is not " + composeCgroupParent}
}

func readCIMemoryWorkflow(t *testing.T) ciMemoryWorkflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	require.NoError(t, err)
	var wf ciMemoryWorkflow
	require.NoError(t, yaml.Unmarshal(data, &wf))
	return wf
}

// runToolchainScript runs in-toolchain-image.sh against a fake docker in an
// empty directory and returns its output and the recorded docker calls.
func runToolchainScript(t *testing.T, env ...string) (string, []string, error) {
	t.Helper()
	bin, state, work := t.TempDir(), t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeToolchainDocker), 0o755))
	calls := filepath.Join(state, "calls")

	cmd := exec.CommandContext(t.Context(), filepath.Join(repoRoot(t), toolchainScript), "toolchain:test", "make", "test")
	cmd.Dir = work
	cmd.Env = append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_DOCKER_CALLS=" + calls,
	}, env...)
	out, runErr := cmd.CombinedOutput()

	var recorded []string
	data, readErr := os.ReadFile(calls)
	if readErr == nil {
		recorded = strings.Split(strings.TrimSpace(string(data)), "\n")
	} else {
		require.ErrorIs(t, readErr, os.ErrNotExist)
	}
	return string(out), recorded, runErr
}

// dockerCreateCall returns the recorded `docker create` call.
func dockerCreateCall(t *testing.T, calls []string) string {
	t.Helper()
	for _, call := range calls {
		if strings.HasPrefix(call, "create ") {
			return call
		}
	}
	require.Failf(t, "no docker create", "calls: %q", calls)
	return ""
}

func TestCIContainersHaveAMemoryLimit(t *testing.T) {
	for _, finding := range ciMemoryFindings(readCIMemoryWorkflow(t)) {
		t.Error(finding)
	}

	data, err := os.ReadFile(filepath.Join(repoRoot(t), devcontainerCompose))
	require.NoError(t, err)
	var compose struct {
		Services map[string]struct {
			MemLimit     string `yaml:"mem_limit"`
			MemswapLimit string `yaml:"memswap_limit"`
			CgroupParent string `yaml:"cgroup_parent"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(data, &compose))
	integration, ok := compose.Services["integration"]
	require.True(t, ok, "%s has no integration service", devcontainerCompose)
	require.NoError(t, composeMemoryFinding(integration.MemLimit, integration.MemswapLimit))
	require.Equal(t, "${GO_TRUSTED_PLATFORM_IT_MEMORY:-16g}", integration.MemLimit,
		"the integration service must take the Makefile's IT_MEMORY")
	require.NoError(t, composeCgroupParentFinding(integration.CgroupParent))

	makefile, err := os.ReadFile(filepath.Join(repoRoot(t), makefilePath))
	require.NoError(t, err)
	text := string(makefile)
	require.Contains(t, text, "\nCI_CGROUP_PARENT ?= ci.slice\n",
		"the Makefile's CI_CGROUP_PARENT must default to ci.slice")
	require.Contains(t, text, "export GO_TRUSTED_PLATFORM_IT_IMAGE=$(IT_IMAGE) GO_TRUSTED_PLATFORM_IT_MEMORY=$(IT_MEMORY) CI_CGROUP_PARENT='$(CI_CGROUP_PARENT)';",
		"make integration-test must pass IT_MEMORY and CI_CGROUP_PARENT to compose")
	start := strings.Index(text, "define run-integration-suite")
	require.GreaterOrEqual(t, start, 0, "the Makefile has no run-integration-suite")
	end := strings.Index(text[start:], "endef")
	require.Positive(t, end, "run-integration-suite has no endef")
	suite := text[start : start+end]
	require.Contains(t, suite, "--memory $(IT_MEMORY) --memory-swap $(IT_MEMORY)",
		"run-integration-suite's docker run must carry the memory limit")
	require.Contains(t, suite, "$(if $(CI_CGROUP_PARENT),--cgroup-parent $(CI_CGROUP_PARENT))",
		"run-integration-suite's docker run must carry the cgroup parent")
}

func TestCIMemoryFindingsRejectEachGap(t *testing.T) {
	toolchainRun := toolchainScript + ` "$TOOLCHAIN_IMAGE" make test`
	cases := map[string]struct {
		wf     ciMemoryWorkflow
		reason string
	}{
		"toolchain step without IN_IMAGE_MEMORY": {
			wf:     ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{"image": {Steps: []ciMemoryStep{{Name: "make test", Run: toolchainRun}}}}},
			reason: "sets no IN_IMAGE_MEMORY",
		},
		"toolchain step above the ceiling": {
			wf: ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{"image": {Steps: []ciMemoryStep{
				{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "17g"}},
			}}}},
			reason: "above the 16g ceiling",
		},
		"toolchain step with a malformed size": {
			wf: ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{"image": {Steps: []ciMemoryStep{
				{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "16GB"}},
			}}}},
			reason: "is not a size in m or g",
		},
		"integration job without IT_MEMORY": {
			wf: ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{
				"image":       {Steps: []ciMemoryStep{{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "16g"}}}},
				"integration": {Steps: []ciMemoryStep{{Name: "leg", Run: "make integration-test-leg LEG=1"}}},
			}},
			reason: "sets no IT_MEMORY",
		},
		"toolchain step clearing the cgroup parent": {
			wf: ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{"image": {Steps: []ciMemoryStep{
				{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "16g", "CI_CGROUP_PARENT": ""}},
			}}}},
			reason: "sets CI_CGROUP_PARENT empty",
		},
		"workflow clearing the cgroup parent": {
			wf: ciMemoryWorkflow{Env: map[string]string{"CI_CGROUP_PARENT": ""}, Jobs: map[string]ciMemoryJob{"image": {Steps: []ciMemoryStep{
				{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "16g"}},
			}}}},
			reason: "sets CI_CGROUP_PARENT empty",
		},
		"integration leg clearing the cgroup parent on the command line": {
			wf: ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{
				"image": {Steps: []ciMemoryStep{{Name: "make test", Run: toolchainRun, Env: map[string]string{"IN_IMAGE_MEMORY": "16g"}}}},
				"integration": {Env: map[string]string{"IT_MEMORY": "16g"}, Steps: []ciMemoryStep{
					{Name: "leg", Run: "make integration-test-leg LEG=1 CI_CGROUP_PARENT= IT_LOG=leg.log"},
				}},
			}},
			reason: "passes an empty CI_CGROUP_PARENT",
		},
		"no toolchain step at all": {
			wf:     ciMemoryWorkflow{Jobs: map[string]ciMemoryJob{"web": {Steps: []ciMemoryStep{{Name: "web", Run: "make web-test-unit"}}}}},
			reason: "no step runs " + toolchainScript,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := ciMemoryFindings(tc.wf)
			require.Len(t, findings, 1)
			var memErr *CIMemoryError
			require.ErrorAs(t, findings[0], &memErr)
			require.Contains(t, memErr.Reason, tc.reason)
		})
	}
}

func TestCIMemoryFindingsAcceptBoundedSteps(t *testing.T) {
	wf := ciMemoryWorkflow{Env: map[string]string{"CI_CGROUP_PARENT": ""}, Jobs: map[string]ciMemoryJob{
		"image": {Env: map[string]string{"CI_CGROUP_PARENT": "ci.slice"}, Steps: []ciMemoryStep{
			{Name: "make test", Run: toolchainScript + " img make test", Env: map[string]string{"IN_IMAGE_MEMORY": "16g"}},
			{Name: "make fmt-check", Run: toolchainScript + " img make fmt-check", Env: map[string]string{"IN_IMAGE_MEMORY": "512m"}},
		}},
		"soak": {Env: map[string]string{"IT_MEMORY": "16g", "CI_CGROUP_PARENT": "ci-soak.slice"}, Steps: []ciMemoryStep{{Name: "soak", Run: `make "$SOAK_TARGET"`}}},
		"web":  {Steps: []ciMemoryStep{{Name: "web", Run: "make web-test-unit CI_CGROUP_PARENT="}}},
	}}
	require.Empty(t, ciMemoryFindings(wf))
}

func TestComposeMemoryFinding(t *testing.T) {
	require.NoError(t, composeMemoryFinding("16g", "16g"))

	var memErr *CIMemoryError
	require.ErrorAs(t, composeMemoryFinding("", ""), &memErr)
	require.Contains(t, memErr.Reason, "has no mem_limit")
	require.ErrorAs(t, composeMemoryFinding("16g", ""), &memErr)
	require.Contains(t, memErr.Reason, "differs from mem_limit")
}

func TestComposeCgroupParentFinding(t *testing.T) {
	require.NoError(t, composeCgroupParentFinding("${CI_CGROUP_PARENT-ci.slice}"))

	var memErr *CIMemoryError
	require.ErrorAs(t, composeCgroupParentFinding(""), &memErr)
	require.Contains(t, memErr.Reason, "has no cgroup_parent")
	require.ErrorAs(t, composeCgroupParentFinding("ci.slice"), &memErr)
	require.Contains(t, memErr.Reason, "is not ${CI_CGROUP_PARENT-ci.slice}")
}

func TestToolchainScriptAppliesTheDefaultLimits(t *testing.T) {
	out, calls, err := runToolchainScript(t)
	require.NoError(t, err, out)
	create := dockerCreateCall(t, calls)
	require.Contains(t, create, "--memory 8g --memory-swap 8g")
	require.Contains(t, create, "--env GOMAXPROCS=16")
	require.Contains(t, create, "--cgroup-parent ci.slice")
}

func TestToolchainScriptTakesTheCgroupParent(t *testing.T) {
	out, calls, err := runToolchainScript(t, "CI_CGROUP_PARENT=ci-heavy.slice")
	require.NoError(t, err, out)
	require.Contains(t, dockerCreateCall(t, calls), "--cgroup-parent ci-heavy.slice")

	out, calls, err = runToolchainScript(t, "CI_CGROUP_PARENT=")
	require.NoError(t, err, out)
	require.NotContains(t, dockerCreateCall(t, calls), "--cgroup-parent",
		"an empty CI_CGROUP_PARENT must pass no parent, for a host with no ci.slice")
}

func TestToolchainScriptTakesTheStepsLimits(t *testing.T) {
	out, calls, err := runToolchainScript(t, "IN_IMAGE_MEMORY=16g", "IN_IMAGE_GOMAXPROCS=8")
	require.NoError(t, err, out)
	create := dockerCreateCall(t, calls)
	require.Contains(t, create, "--memory 16g --memory-swap 16g")
	require.Contains(t, create, "--env GOMAXPROCS=8")
}

func TestToolchainScriptRejectsABadLimit(t *testing.T) {
	cases := map[string]struct {
		env    string
		reason string
	}{
		"memory without a unit":      {env: "IN_IMAGE_MEMORY=16", reason: "IN_IMAGE_MEMORY must be a size"},
		"memory in gigabytes":        {env: "IN_IMAGE_MEMORY=16GB", reason: "IN_IMAGE_MEMORY must be a size"},
		"zero memory":                {env: "IN_IMAGE_MEMORY=0g", reason: "IN_IMAGE_MEMORY must be a size"},
		"zero GOMAXPROCS":            {env: "IN_IMAGE_GOMAXPROCS=0", reason: "IN_IMAGE_GOMAXPROCS must be a positive integer"},
		"word GOMAXPROCS":            {env: "IN_IMAGE_GOMAXPROCS=all", reason: "IN_IMAGE_GOMAXPROCS must be a positive integer"},
		"cgroup parent with a space": {env: "CI_CGROUP_PARENT=ci slice", reason: "CI_CGROUP_PARENT must be a cgroup name"},
		"cgroup parent as an option": {env: "CI_CGROUP_PARENT=--privileged", reason: "CI_CGROUP_PARENT must be a cgroup name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, calls, err := runToolchainScript(t, tc.env)
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 2, exitErr.ExitCode())
			require.Contains(t, out, tc.reason)
			require.Empty(t, calls, "no container may start with a bad limit")
		})
	}
}
