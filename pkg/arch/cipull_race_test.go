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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRegistryDocker is a docker CLI over a directory: tags/<ref> holds the image
// id a reference names, containers/<name> a created container. It knows the
// commands the integration legs' registry pull step runs.
const fakeRegistryDocker = `#!/usr/bin/env bash
s=$FAKE_DOCKER_STATE
enc() { printf '%s' "$1" | tr '/:@' '___'; }
resolve() {
  if [ -f "$s/tags/$(enc "$1")" ]; then cat "$s/tags/$(enc "$1")"
  elif [ "$1" = "$FAKE_IMAGE_ID" ]; then echo "$1"
  else
    for f in "$s"/tags/*; do [ -f "$f" ] && [ "$(cat "$f")" = "$1" ] && { echo "$1"; return 0; }; done
    echo "Error response from daemon: No such image: $1" >&2; return 1; fi
}
# A container's id is its name here; FAKE_LOCK_CREATED is the creation time
# every container reports, empty as in run 45379249259.
inspect_container() {
  [ "$2" = '{{.Id}} {{.Created}}' ] || { echo "fake docker: inspect -f $2" >&2; exit 2; }
  [ -e "$s/containers/$1" ] || { echo "Error: No such container: $1" >&2; exit 1; }
  echo "$1 ${FAKE_LOCK_CREATED-}"
}
# The CLI's context: DOCKER_CONTEXT, else default under DOCKER_HOST, else the
# currentContext of the config in DOCKER_CONFIG, whose contexts/ must know it.
cfg=${DOCKER_CONFIG:-$HOME/.docker}
ctx=default re='"currentContext": *"([^"]*)"'
if [ -n "${DOCKER_CONTEXT:-}" ]; then ctx=$DOCKER_CONTEXT
elif [ -z "${DOCKER_HOST:-}" ] && [ -f "$cfg/config.json" ] && [[ $(cat "$cfg/config.json") =~ $re ]]; then
  ctx=${BASH_REMATCH[1]}
fi
if [ "$ctx" != default ] && [ ! -e "$cfg/contexts/$ctx" ]; then
  echo "context \"$ctx\": context not found" >&2; exit 1
fi
# The CLI falls back to an installed native credential helper whenever its
# config.json holds no auths (DetectDefaultStore); call it as the CLI would.
case "$1" in
  login|push|pull)
    if ! { [ -f "$cfg/config.json" ] && [[ $(cat "$cfg/config.json") == *'"auths"'* ]]; }; then
      for h in pass secretservice; do
        if command -v "docker-credential-$h" >/dev/null; then echo "$1" | "docker-credential-$h" list; break; fi
      done
    fi
    if [ "$1" != login ]; then
      if [ -f "$cfg/config.json" ]; then cat "$cfg/config.json" > "$s/$1-config"; else : > "$s/$1-config"; fi
    fi ;;
esac
case "$1" in
  context) [ "$2" = show ] || { echo "fake docker: $*" >&2; exit 2; }; echo "$ctx" ;;
  login) cat >/dev/null; echo "$*" >> "$s/login"; exit 0 ;;
  push) echo "$ctx" >> "$s/push-context"; resolve "$2" >/dev/null || exit 1; echo "$2" >> "$s/pushed" ;;
  pull)
    echo "$ctx" >> "$s/pull-context"
    echo "$2" >> "$s/pulled"
    [ -z "${FAKE_PULL_FAILS:-}" ] || { echo "Error response from daemon: pull failed" >&2; exit 1; }
    # FAKE_PULL_ERRS: the ;-separated errors of the daemon's successive pulls.
    n=$(wc -l < "$s/pull-context")
    IFS=';' read -ra errs <<< "${FAKE_PULL_ERRS:-}"
    [ -z "${errs[n-1]:-}" ] || { echo "Error response from daemon: ${errs[n-1]}" >&2; exit 1; }
    echo "${FAKE_PULLED_ID:-$FAKE_IMAGE_ID}" > "$s/tags/$(enc "$2")" ;;
  tag) echo "$ctx" >> "$s/tag-context"; id=$(resolve "$2") || exit 1; echo "$id" > "$s/tags/$(enc "$3")" ;;
  rmi) rm "$s/tags/$(enc "$2")" 2>/dev/null || exit 1 ;;
  import) [ "$2" = - ] || { echo "fake docker: $*" >&2; exit 2; }; cat >/dev/null; echo sha256:0000 > "$s/tags/$(enc "$3")" ;;
  inspect) inspect_container "$4" "$3" ;;
  image)
    [ "$2" = inspect ] || { echo "fake docker: $*" >&2; exit 2; }
    [ "$3" = -f ] || { resolve "$3" >/dev/null || exit 1; echo '[]'; exit 0; }
    id=$(resolve "$5") || exit 1
    case "$4" in
      '{{.Id}}') echo "$id" ;;
      '{{json .RootFS.Layers}}')
        if [ -n "${FAKE_PULLED_LAYERS:-}" ] && [ "$id" = "$FAKE_PULLED_ID" ]; then echo "$FAKE_PULLED_LAYERS"
        else echo "$FAKE_LAYERS"; fi ;;
      *) echo "fake docker: $*" >&2; exit 2 ;;
    esac ;;
  create)
    [ "$2 $3 $4" = "--pull never --name" ] || { echo "fake docker: $*" >&2; exit 2; }
    [ ! -e "$s/containers/$5" ] || { echo "Conflict: the container name $5 is already in use" >&2; exit 1; }
    id=$(resolve "$6") || exit 1
    echo "$id" > "$s/containers/$5"; echo "$5" ;;
  container)
    case "$2" in
      inspect) [ "$3" = -f ] || { echo "fake docker: $*" >&2; exit 2; }; inspect_container "$5" "$4" ;;
      *) rm -f "$s/containers/$3" ;;
    esac ;;
  rm) rm -f "$s/containers/$2" ;;
  *) echo "fake docker: $*" >&2; exit 2 ;;
esac
`

// twoLegLock is the image lock both legs source. Leg B pulled first; its
// first image_lock waits while leg A, which pulled too, runs its whole pull
// step under the lock. Leg B then takes the lock.
const twoLegLock = `image_lock() {
  echo "${1:-}" >> "$FAKE_DOCKER_STATE/lock-names"
  if [ -z "$LEG_A_DONE" ]; then
    export LEG_A_DONE=1
    if GITHUB_ENV=$LEG_A_ENV GITHUB_OUTPUT=$LEG_A_OUT IT_LEASE=lease-a bash -e "$PULL_STEP" > "$LEG_A_LOG" 2>&1; then
      echo 0 > "$LEG_A_RC"
    else
      echo 1 > "$LEG_A_RC"
    fi
  fi
  return 0
}
image_unlock() { :; }
`

type pullLeg struct {
	rc     string
	output string
	log    string
	// pulled is every reference the shared fake daemon was asked to pull,
	// one per line (set on leg B only: both legs share the daemon).
	pulled string
}

// The fixture registry and the reference a leg rebuilds from it and the
// image_tag the image job's push step emits for IT_LEASE_ID sha256:1111.
const (
	ciFixtureRegistry = "registry.invalid:5000"
	ciFixtureImageRef = ciFixtureRegistry + "/go-trusted-platform/it-image:1111"
)

// runTwoLegPull runs the pull step as two legs on one cold daemon: both
// pulls succeed before either leg acquires the image lock, then leg A and
// leg B acquire it in turn.
func runTwoLegPull(t *testing.T, step string, env ...string) (a, b pullLeg, state string) {
	t.Helper()
	dir := t.TempDir()
	bin, tmp := filepath.Join(dir, "bin"), filepath.Join(dir, "runner-temp")
	state = filepath.Join(dir, "state")
	for _, d := range []string{bin, filepath.Join(state, "tags"), filepath.Join(state, "containers"), tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeRegistryDocker), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "image-lock.sh"), []byte(twoLegLock), 0o644))
	stepFile := filepath.Join(dir, "pull.sh")
	require.NoError(t, os.WriteFile(stepFile, []byte(step), 0o644))

	const layers = `["sha256:aaaa","sha256:bbbb"]`
	sum := sha256.Sum256([]byte(layers + "\n"))
	file := func(name string) string { return filepath.Join(dir, name) }
	for _, name := range []string{"a.env", "a.out", "b.env", "b.out"} {
		require.NoError(t, os.WriteFile(file(name), nil, 0o644))
	}

	cmd := exec.Command("bash", "-e", stepFile)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_STATE="+state,
		"HOME="+dir, "DOCKER_CONFIG=", "DOCKER_CONTEXT=", "DOCKER_HOST=",
		"FAKE_IMAGE_ID=sha256:1111",
		"FAKE_LAYERS="+layers,
		"RUNNER_TEMP="+tmp,
		"IT_REGISTRY=registry.invalid:5000",
		"IT_IMAGE_TAG=1111",
		"IT_IMAGE=go-trusted-platform-it:content",
		"IT_IMAGE_IDENTITY="+hex.EncodeToString(sum[:]),
		"REGISTRY_USER=", "REGISTRY_PASSWORD=",
		"IT_LEASE=lease-b",
		"GITHUB_ENV="+file("b.env"),
		"GITHUB_OUTPUT="+file("b.out"),
		"PULL_STEP="+stepFile,
		"LEG_A_ENV="+file("a.env"),
		"LEG_A_OUT="+file("a.out"),
		"LEG_A_LOG="+file("a.log"),
		"LEG_A_RC="+file("a.rc"),
	)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	b.rc, b.log = "0", string(out)
	if err != nil {
		b.rc = err.Error()
	}
	read := func(name string) string {
		data, _ := os.ReadFile(file(name))
		return strings.TrimSpace(string(data))
	}
	// Each leg rebuilds the reference from IT_REGISTRY and IT_IMAGE_TAG, and
	// the reference the first leg pulled stays for the other leg to re-tag from.
	tag := "1111"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "IT_IMAGE_TAG="); ok {
			tag = v
		}
	}
	require.FileExists(t, filepath.Join(state, "tags", "registry.invalid_5000_go-trusted-platform_it-image_"+tag),
		"the legs pull registry.invalid:5000/go-trusted-platform/it-image:%s:\n%s", tag, out)
	a = pullLeg{rc: read("a.rc"), output: read("a.out"), log: read("a.log")}
	b.output = read("b.out")
	data, _ := os.ReadFile(filepath.Join(state, "pulled"))
	b.pulled = strings.TrimSpace(string(data))
	return a, b, state
}

// Codex review of #1919 (P1): two legs on one cold daemon both pull the
// registry reference before either takes the image lock. The first to take
// it must not remove the reference the second then resolves, and a leg that
// finds no reference falls back to its build instead of failing.
func TestCIRegistryPullSurvivesTwoLegsOnOneDaemon(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	_, steps := ciRawJob(t, wf, ciLegJob)
	var step string
	for _, s := range steps {
		if s.ID == "pull" {
			step = s.Run
		}
	}
	require.NotEmpty(t, step, "job %s has no step with id pull", ciLegJob)

	a, b, _ := runTwoLegPull(t, step)
	require.Equal(t, "0", a.rc, "leg A, first to take the lock:\n%s", a.log)
	require.Contains(t, a.output, "leased=true", "leg A:\n%s", a.log)
	require.Equal(t, "0", b.rc, "leg B, second to take the lock:\n%s", b.log)
	require.Contains(t, b.output, "leased=true", "leg B:\n%s", b.log)
	// Legs sharing a daemon pull the image once (#2386); the one pull is of
	// the registry-prefixed path-bound reference the image job pushed.
	require.Equal(t, []string{ciFixtureImageRef}, strings.Fields(b.pulled),
		"the legs pull the registry-prefixed image path once per daemon:\nA:\n%s\nB:\n%s", a.log, b.log)
}

// twoProducerLock is the image lock both producers source. Producer B
// tagged the registry reference first; when it drops the lock, producer A,
// which built the same image id on the same daemon, runs its whole push
// step. Producer B then pushes.
const twoProducerLock = `image_lock() { return 0; }
image_unlock() {
  if [ -z "$PRODUCER_A_DONE" ]; then
    export PRODUCER_A_DONE=1
    if GITHUB_OUTPUT=$PRODUCER_A_OUT bash -e "$PUSH_STEP" > "$PRODUCER_A_LOG" 2>&1; then
      echo 0 > "$PRODUCER_A_RC"
    else
      echo 1 > "$PRODUCER_A_RC"
    fi
  fi
}
`

// Codex review of #1919 (P1, round 2): two producers of one image id on one
// daemon share the registry reference. Producer A's exit must not remove
// the reference producer B is about to push; the reaper owns it.
func TestCIRegistryPushSurvivesTwoProducersOnOneDaemon(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	_, steps := ciRawJob(t, wf, "integration-image")
	var step string
	for _, s := range steps {
		if s.ID == "push" {
			step = s.Run
		}
	}
	require.NotEmpty(t, step, "job integration-image has no step with id push")

	dir := t.TempDir()
	bin, state, tmp := filepath.Join(dir, "bin"), filepath.Join(dir, "state"), filepath.Join(dir, "runner-temp")
	for _, d := range []string{bin, filepath.Join(state, "tags"), filepath.Join(state, "containers"), tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeRegistryDocker), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "image-lock.sh"), []byte(twoProducerLock), 0o644))
	file := func(name string) string { return filepath.Join(dir, name) }
	require.NoError(t, os.WriteFile(file("push.sh"), []byte(step), 0o644))
	for _, name := range []string{"a.out", "b.out"} {
		require.NoError(t, os.WriteFile(file(name), nil, 0o644))
	}

	cmd := exec.Command("bash", "-e", file("push.sh"))
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_STATE="+state,
		"HOME="+dir, "DOCKER_CONFIG=", "DOCKER_CONTEXT=", "DOCKER_HOST=",
		"FAKE_IMAGE_ID=sha256:1111",
		"RUNNER_TEMP="+tmp,
		"IT_REGISTRY=registry.invalid:5000",
		"IT_LEASE_ID=sha256:1111",
		"REGISTRY_USER=ci", "REGISTRY_PASSWORD=secret",
		"GITHUB_OUTPUT="+file("b.out"),
		"PUSH_STEP="+file("push.sh"),
		"PRODUCER_A_OUT="+file("a.out"),
		"PRODUCER_A_LOG="+file("a.log"),
		"PRODUCER_A_RC="+file("a.rc"),
	)
	out, err := cmd.CombinedOutput()
	read := func(name string) string {
		data, _ := os.ReadFile(file(name))
		return strings.TrimSpace(string(data))
	}
	require.Equal(t, "0", read("a.rc"), "producer A:\n%s", read("a.log"))
	require.NoError(t, err, "producer B, which pushes after producer A exits:\n%s", out)
	tag := "image_tag=1111"
	require.Equal(t, tag, read("a.out"))
	require.Equal(t, tag, read("b.out"))
	pushed, err := os.ReadFile(filepath.Join(state, "pushed"))
	require.NoError(t, err)
	pushedRef := "registry.invalid:5000/go-trusted-platform/it-image:1111"
	require.Equal(t, []string{pushedRef, pushedRef}, strings.Fields(string(pushed)), "both producers push")
	// The per-job Docker configs are gone with their jobs.
	left, err := filepath.Glob(filepath.Join(tmp, "docker-config.*"))
	require.NoError(t, err)
	require.Empty(t, left)
}

// singleLegLock is the image-lock.sh of a job alone on its daemon, with the
// workflow's take_lease.
const singleLegLock = `image_lock() { return 0; }
image_unlock() { :; }
take_lease() {
  id=$(docker image inspect -f '{{.Id}}' "$IT_IMAGE" 2>/dev/null) || return 1
  docker create --pull never --name "$lease" "$id" true >/dev/null || return 1
  [ "$(docker image inspect -f '{{.Id}}' "$IT_IMAGE" 2>/dev/null)" = "$id" ] && return 0
  docker rm "$lease" >/dev/null 2>&1 || true
  return 1
}
`

// fakeBuildMake answers the Load step's fallback: `make -s it-image` names
// the leg's image and `make docker-build-it` tags it as FAKE_BUILT_ID on the
// fake daemon.
const fakeBuildMake = `#!/usr/bin/env bash
s=$FAKE_DOCKER_STATE
if [ "$1 $2" = "-s it-image" ]; then echo "$FAKE_BUILT_IMAGE"; exit 0; fi
[ "$1" = docker-build-it ] || { echo "fake make: $*" >&2; exit 2; }
for a in "$@"; do case "$a" in IT_IMAGE=*) img=${a#IT_IMAGE=} ;; esac; done
echo "$img" >> "$s/built"
echo "$FAKE_BUILT_ID" > "$s/tags/$(printf '%s' "$img" | tr '/:@' '___')"
`

// registryRun is what a run of workflow steps left on the fake daemon and in
// the job's GITHUB_ENV and GITHUB_OUTPUT.
type registryRun struct {
	state, tmp  string
	env, output string
	log         string
	err         error
}

func (r registryRun) read(name string) string {
	data, _ := os.ReadFile(filepath.Join(r.state, name))
	return strings.TrimSpace(string(data))
}

// ciStepRun returns the run script of the step of job whose id or name is key.
func ciStepRun(t *testing.T, job, key string) string {
	t.Helper()
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	_, steps := ciRawJob(t, wf, job)
	for _, s := range steps {
		if s.ID == key || s.Name == key {
			return s.Run
		}
	}
	t.Fatalf("job %s has no step %q", job, key)
	return ""
}

// runRegistrySteps runs steps in order, as one job alone on a fake daemon,
// until one fails. home is the runner's HOME, which setup may fill; env
// overrides the defaults.
func runRegistrySteps(t *testing.T, setup func(home string), env []string, steps ...string) registryRun {
	t.Helper()
	dir := t.TempDir()
	bin, state, tmp, home := filepath.Join(dir, "bin"), filepath.Join(dir, "state"), filepath.Join(dir, "runner-temp"), filepath.Join(dir, "home")
	for _, d := range []string{bin, filepath.Join(state, "tags"), filepath.Join(state, "containers"), tmp, home} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeRegistryDocker), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "make"), []byte(fakeBuildMake), 0o755))
	sleep := "#!/usr/bin/env bash\necho \"$*\" >> \"$FAKE_DOCKER_STATE/sleeps\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "sleep"), []byte(sleep), 0o755))
	for _, h := range []string{"docker-credential-pass", "docker-credential-secretservice"} {
		helper := "#!/usr/bin/env bash\necho \"" + h + " $* $(cat)\" >> \"$FAKE_DOCKER_STATE/helper-calls\"\n"
		require.NoError(t, os.WriteFile(filepath.Join(bin, h), []byte(helper), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "image-lock.sh"), []byte(singleLegLock), 0o644))
	if setup != nil {
		setup(home)
	}
	envFile, outFile := filepath.Join(dir, "job.env"), filepath.Join(dir, "job.out")
	for _, f := range []string{envFile, outFile} {
		require.NoError(t, os.WriteFile(f, nil, 0o644))
	}

	const layers = `["sha256:aaaa","sha256:bbbb"]`
	sum := sha256.Sum256([]byte(layers + "\n"))
	base := append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_STATE="+state,
		"HOME="+home, "DOCKER_CONFIG=", "DOCKER_CONTEXT=", "DOCKER_HOST=", "DEVCACHE_GOPROXY=",
		"FAKE_IMAGE_ID=sha256:1111",
		"FAKE_LAYERS="+layers,
		"FAKE_BUILT_IMAGE=go-trusted-platform-it:leg-build",
		"FAKE_BUILT_ID=sha256:2222",
		"RUNNER_TEMP="+tmp,
		"IT_REGISTRY="+ciFixtureRegistry,
		"IT_LEASE_ID=sha256:1111",
		"IT_IMAGE_TAG=1111",
		"IT_IMAGE=go-trusted-platform-it:content",
		"IT_IMAGE_IDENTITY="+hex.EncodeToString(sum[:]),
		"REGISTRY_USER=ci", "REGISTRY_PASSWORD=secret",
		"IT_LEASE=lease-leg",
		"GITHUB_ENV="+envFile,
		"GITHUB_OUTPUT="+outFile,
	)
	base = append(base, env...)

	r := registryRun{state: state, tmp: tmp}
	var log strings.Builder
	for i, step := range steps {
		f := filepath.Join(dir, fmt.Sprintf("step%d.sh", i))
		require.NoError(t, os.WriteFile(f, []byte(step), 0o644))
		cmd := exec.Command("bash", "-e", f)
		cmd.Env = base
		out, err := cmd.CombinedOutput()
		log.Write(out)
		if err != nil {
			r.err = fmt.Errorf("step %d: %w", i, err)
			break
		}
		// Hand a push step's image_tag output to the later steps, as the
		// workflow binds needs.integration-image.outputs.image_tag.
		data, _ := os.ReadFile(outFile)
		for _, line := range strings.Split(string(data), "\n") {
			if tag, ok := strings.CutPrefix(line, "image_tag="); ok {
				base = append(base, "IT_IMAGE_TAG="+tag)
			}
		}
	}
	r.log = log.String()
	data, _ := os.ReadFile(envFile)
	r.env = string(data)
	data, _ = os.ReadFile(outFile)
	r.output = string(data)
	return r
}

// TestCIRegistryPullFallsBackToALeasedBuild holds Codex P1 (b) on #1919:
// a leg whose pull fails, or gives other layers than the image job's, leases
// nothing from the registry and leaves the pull step to the Load step's
// fallback build, which the leg ends holding a lease on.
func TestCIRegistryPullFallsBackToALeasedBuild(t *testing.T) {
	pull := ciStepRun(t, ciLegJob, "pull")
	load := ciStepRun(t, ciLegJob, "Load the integration image")
	for name, env := range map[string][]string{
		"pull fails":   {"FAKE_PULL_FAILS=1"},
		"other layers": {"FAKE_PULLED_ID=sha256:9999", `FAKE_PULLED_LAYERS=["sha256:cccc"]`},
	} {
		t.Run(name, func(t *testing.T) {
			r := runRegistrySteps(t, nil, env, pull, load)
			require.NoError(t, r.err, r.log)
			require.NotContains(t, r.output, "leased=true", "the pull step accepted a rejected image:\n%s", r.log)
			require.Contains(t, r.log, "building this leg's image")
			require.Equal(t, "go-trusted-platform-it:leg-build", r.read("built"), "the Load step's fallback build:\n%s", r.log)
			require.NotContains(t, r.env, "IT_LEASE_ID=sha256:9999")
			require.NotContains(t, r.env, "IT_LEASE_ID=sha256:1111")
			require.Contains(t, r.env, "IT_IMAGE=go-trusted-platform-it:leg-build\n")
			require.Contains(t, r.env, "IT_LEASE_ID=sha256:2222\n")
			leases, err := os.ReadDir(filepath.Join(r.state, "containers"))
			require.NoError(t, err)
			require.Len(t, leases, 1, "the leg holds one lease")
			require.Equal(t, "lease-leg", leases[0].Name())
			require.Equal(t, "sha256:2222", r.read(filepath.Join("containers", "lease-leg")), "the lease is on the rebuilt image")
		})
	}
}

// TestCIRegistryPullTakesThePushedReference runs the image job's push step and
// then the leg's pull step on one daemon: the pull must ask for exactly the
// reference the push pushed, rebuilt from the image_tag it emitted, and lease it.
func TestCIRegistryPullTakesThePushedReference(t *testing.T) {
	r := runRegistrySteps(t, nil, nil, ciStepRun(t, ciImageJob, "push"), ciStepRun(t, ciLegJob, "pull"))
	require.NoError(t, r.err, r.log)
	var tag string
	for _, line := range strings.Split(r.output, "\n") {
		if v, ok := strings.CutPrefix(line, "image_tag="); ok {
			tag = v
		}
	}
	require.NotEmpty(t, tag, "the push step emits no image_tag:\n%s", r.log)
	require.Equal(t, ciFixtureRegistry+"/go-trusted-platform/it-image:"+tag, r.read("pushed"), "the push step's reference:\n%s", r.log)
	// On the push step's daemon the pushed reference is already there, so the
	// leg pulls nothing (#2386, one pull per daemon).
	require.Empty(t, r.read("pulled"), "the leg pulled an image its daemon holds:\n%s", r.log)
	require.Contains(t, r.output, "leased=true", r.log)

	// A leg on another daemon has no copy: drop the pushed reference (named
	// from the push record, not the workflow's path) and the leg must pull
	// exactly the pushed path-only reference.
	forget := `docker rmi "$(cat "$FAKE_DOCKER_STATE/pushed")"`
	r = runRegistrySteps(t, nil, nil, ciStepRun(t, ciImageJob, "push"), forget, ciStepRun(t, ciLegJob, "pull"))
	require.NoError(t, r.err, r.log)
	require.Equal(t, ciFixtureRegistry+"/go-trusted-platform/it-image:"+tag, r.read("pushed"), "the push step's reference:\n%s", r.log)
	require.Equal(t, r.read("pushed"), r.read("pulled"), "the pull step's reference:\n%s", r.log)
	require.Contains(t, r.output, "leased=true", r.log)
}

// ciImageLockFn returns the workflow's image_lock function, dedented, after
// checking that every copy of it in ci.yml is the same text.
func ciImageLockFn(t *testing.T) string {
	t.Helper()
	return ciShellFn(t, "image_lock")
}

// ciShellFn returns the shell function name as ci.yml defines it, checking
// that its four copies agree.
func ciShellFn(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	require.NoError(t, err)
	var copies []string
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != name+"() {" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
		var fn strings.Builder
		for _, l := range lines[i:] {
			fn.WriteString(strings.TrimPrefix(l, indent) + "\n")
			if l == indent+"}" {
				break
			}
		}
		copies = append(copies, fn.String())
	}
	require.Len(t, copies, 4, "ci.yml defines %s in four steps", name)
	for i, c := range copies[1:] {
		require.Equal(t, copies[0], c, "%s copy %d differs from the first", name, i+2)
	}
	return copies[0]
}

// runImageLock runs the workflow's image_lock against the fake docker while
// another leg holds holder, whose container reports created as its creation
// time. The holder releases it at the waiter's third sleep.
func runImageLock(t *testing.T, created, holder string, args ...string) (log, state string) {
	t.Helper()
	dir := t.TempDir()
	bin, state := filepath.Join(dir, "bin"), filepath.Join(dir, "state")
	for _, d := range []string{bin, filepath.Join(state, "tags"), filepath.Join(state, "containers")} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeRegistryDocker), 0o755))
	if holder != "" {
		require.NoError(t, os.WriteFile(filepath.Join(state, "containers", holder), []byte("sha256:0000\n"), 0o644))
	}
	script := ciImageLockFn(t) + `sleeps=0
sleep() {
  sleeps=$((sleeps + 1))
  if [ "$sleeps" -ge 3 ] && [ -n "$HOLDER" ]; then docker rm "$HOLDER" >/dev/null; fi
}
image_lock "$@"
echo "sleeps=$sleeps lock=$IMAGE_LOCK_ID"
`
	f := filepath.Join(dir, "lock.sh")
	require.NoError(t, os.WriteFile(f, []byte(script), 0o644))
	cmd := exec.Command("bash", append([]string{"-e", f}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_DOCKER_STATE="+state,
		"HOME="+dir, "DOCKER_CONFIG=", "DOCKER_CONTEXT=", "DOCKER_HOST=",
		"FAKE_LOCK_CREATED="+created,
		"HOLDER="+holder,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "image_lock:\n%s", out)
	return string(out), state
}

// Run 45379249259: docker inspect gave the live lock an empty creation time,
// and date -d "" is today 00:00, so every waiter removed the held lock as
// stale. Only a known creation time 600 s old makes a lock stale.
func TestCIImageLockRemovesOnlyAKnownStaleLock(t *testing.T) {
	const lock = "go-trusted-platform-ci-image-lock"
	for name, tc := range map[string]struct {
		created string
		stale   bool
	}{
		"empty creation time":      {created: ""},
		"unparsable creation time": {created: "not-a-time"},
		"fresh lock":               {created: time.Now().UTC().Format(time.RFC3339Nano)},
		"stale lock":               {created: time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339Nano), stale: true},
	} {
		t.Run(name, func(t *testing.T) {
			log, _ := runImageLock(t, tc.created, lock)
			require.Contains(t, log, "lock="+lock, log)
			if tc.stale {
				require.Contains(t, log, "removing the stale image lock "+lock, log)
				require.Contains(t, log, "sleeps=0 ", log)
				return
			}
			require.NotContains(t, log, "removing the stale image lock", "the waiter removed a live lock:\n%s", log)
			require.Contains(t, log, "sleeps=3 ", "the waiter took the lock before its holder released it:\n%s", log)
		})
	}
}

// image_lock takes an optional lock name; every lock is a container of the
// one go-trusted-platform-ci-image-lock:base image.
func TestCIImageLockTakesANamedLock(t *testing.T) {
	const lock = "go-trusted-platform-ci-pull-0123456789ab"
	log, state := runImageLock(t, "", lock, lock)
	require.Contains(t, log, "lock="+lock, log)
	require.Contains(t, log, "sleeps=3 ", "the waiter took the named lock before its holder released it:\n%s", log)
	require.FileExists(t, filepath.Join(state, "containers", lock))
	require.NoFileExists(t, filepath.Join(state, "containers", "go-trusted-platform-ci-image-lock"), "a named lock took the default lock too")
	require.FileExists(t, filepath.Join(state, "tags", "go-trusted-platform-ci-image-lock_base"))
	require.NoFileExists(t, filepath.Join(state, "tags", lock+"_base"))
}

// TestCIRegistryPullKeepsItsLockPastTheImageLockAge is Codex round 2 P1 on
// #2386: the pull step holds its per-digest lock across every docker pull
// and retry, so a waiting leg must not call that lock stale while a slow
// pull still runs. The waiter takes the lock with the step's own arguments
// against a live holder created 700 s ago (past the image lock's 600 s), and
// must wait for the holder instead of removing its lock; each docker pull is
// bounded so the holder ends well before the pull lock's stale age.
func TestCIRegistryPullKeepsItsLockPastTheImageLockAge(t *testing.T) {
	step := ciStepRun(t, ciLegJob, "pull")
	const lock = "go-trusted-platform-ci-pull-0123456789ab"
	var args []string
	var pulls []string
	for _, line := range strings.Split(step, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, `image_lock "go-trusted-platform-ci-pull-${digest:0:12}"`); ok {
			args = strings.Fields(strings.TrimSuffix(strings.TrimSpace(rest), "|| exit 1"))
		}
		if strings.Contains(line, "docker pull ") {
			pulls = append(pulls, line)
		}
	}
	require.NotEmpty(t, pulls, "the pull step runs docker pull:\n%s", step)
	stale := 600
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		require.NoError(t, err, "the pull lock's stale age: %q", args)
		stale = n
	}
	for _, p := range pulls {
		m := regexp.MustCompile(`\btimeout (\d+) docker pull `).FindStringSubmatch(p)
		require.NotNil(t, m, "a docker pull under the pull lock runs unbounded: %s", p)
		limit, _ := strconv.Atoi(m[1])
		// Three tries and 5 + 15 s of retry sleeps must end before a waiter
		// may call the lock stale.
		require.Less(t, 3*limit+20, stale, "the bounded pulls outlive the pull lock's stale age %d s: %s", stale, p)
	}

	created := time.Now().Add(-700 * time.Second).UTC().Format(time.RFC3339Nano)
	log, state := runImageLock(t, created, lock, append([]string{lock}, args...)...)
	require.NotContains(t, log, "removing the stale image lock", "a waiter removed the lock of a pull still running at 700 s:\n%s", log)
	require.Contains(t, log, "sleeps=3 ", "the waiter took the pull lock before its holder released it:\n%s", log)
	require.Contains(t, log, "lock="+lock, log)
	require.FileExists(t, filepath.Join(state, "containers", lock))
}

// Run 45379249259: five legs on one daemon pulled one digest at once, and
// containerd failed them on its ref lock. A leg takes the digest's pull lock
// and skips the pull when a leg before it left the image on the daemon.
func TestCIRegistryPullPullsADigestOncePerDaemon(t *testing.T) {
	step := ciStepRun(t, ciLegJob, "pull")
	// Each leg rebuilds the reference from IT_REGISTRY and the image job's
	// image_tag (the image ID's hex), so the lock is named after the
	// reference's hash: one lock, and one pull, per image per daemon.
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for name, tag := range map[string]string{
		"image id tag": hex64,
		"other tag":    "v1.2-test",
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256([]byte("registry.invalid:5000/go-trusted-platform/it-image:" + tag))
			lock := hex.EncodeToString(sum[:])[:12]
			a, b, state := runTwoLegPull(t, step, "IT_IMAGE_TAG="+tag)
			require.Equal(t, "0", a.rc, "leg A:\n%s", a.log)
			require.Contains(t, a.output, "leased=true", "leg A:\n%s", a.log)
			require.Equal(t, "0", b.rc, "leg B:\n%s", b.log)
			require.Contains(t, b.output, "leased=true", "leg B:\n%s", b.log)
			pulls, _ := os.ReadFile(filepath.Join(state, "pull-context"))
			require.Equal(t, 1, strings.Count(string(pulls), "\n"), "two legs on one daemon pulled tag %s:\nA:\n%s\nB:\n%s", tag, a.log, b.log)
			names, _ := os.ReadFile(filepath.Join(state, "lock-names"))
			require.Contains(t, strings.Split(string(names), "\n"), "go-trusted-platform-ci-pull-"+lock, "lock names taken:\n%s", names)
		})
	}
}

// overlapDocker wraps fakeRegistryDocker ($FAKE_DOCKER_REAL): container names
// are reserved atomically (mkdir), as the daemon does, and the first pull
// waits until the other leg either contends for a pull lock held during that
// pull or starts a pull of its own.
const overlapDocker = `#!/usr/bin/env bash
s=$FAKE_DOCKER_STATE real=$FAKE_DOCKER_REAL
case "$1" in
  create)
    n=$5
    if ! mkdir "$s/names/$n" 2>/dev/null; then
      case $n in go-trusted-platform-ci-pull-*)
        [ ! -e "$s/first-pull" ] || : > "$s/pull-lock-contended" ;;
      esac
      echo "Conflict: the container name $n is already in use" >&2; exit 1
    fi
    "$real" "$@"; rc=$?
    [ "$rc" -eq 0 ] || rmdir "$s/names/$n"
    exit "$rc" ;;
  rm) "$real" "$@"; rc=$?; rmdir "$s/names/$2" 2>/dev/null; exit "$rc" ;;
  container)
    "$real" "$@"; rc=$?
    [ "$2" != rm ] || rmdir "$s/names/$3" 2>/dev/null
    exit "$rc" ;;
  pull)
    if mkdir "$s/first-pull" 2>/dev/null; then
      for ((i = 0; ; i++)); do
        [ -e "$s/pull-lock-contended" ] || [ -e "$s/second-pull" ] && break
        [ "$i" -lt 1200 ] || { echo "fake docker: the other leg never reached the pull lock" >&2; exit 1; }
        command sleep 0.05
      done
    else
      : > "$s/second-pull"
    fi
    exec "$real" "$@" ;;
  *) exec "$real" "$@" ;;
esac
`

// TestCIRegistryPullHoldsItsPullLockAcrossThePull runs two legs of the pull
// step at once on one fake daemon, with the workflow's own image_lock and
// image_unlock. The first pull is held until the other leg has tried the
// same pull lock (or has started a pull of its own): a step that holds the
// pull lock across docker pull makes the other leg wait and then reuse the
// image, so one pull starts and both legs lease it.
func TestCIRegistryPullHoldsItsPullLockAcrossThePull(t *testing.T) {
	step := ciStepRun(t, ciLegJob, "pull")
	dir := t.TempDir()
	bin, tmp, state := filepath.Join(dir, "bin"), filepath.Join(dir, "runner-temp"), filepath.Join(dir, "state")
	for _, d := range []string{bin, filepath.Join(state, "tags"), filepath.Join(state, "containers"), filepath.Join(state, "names"), tmp} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	realDocker := filepath.Join(dir, "fake-docker")
	require.NoError(t, os.WriteFile(realDocker, []byte(fakeRegistryDocker), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(overlapDocker), 0o755))
	// The lock's 1 s retry runs as a 50 ms poll here.
	lockLib := ciShellFn(t, "image_lock") + ciShellFn(t, "image_unlock") + "sleep() { command sleep 0.05; }\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "image-lock.sh"), []byte(lockLib), 0o644))
	stepFile := filepath.Join(dir, "pull.sh")
	require.NoError(t, os.WriteFile(stepFile, []byte(step), 0o644))

	const layers = `["sha256:aaaa","sha256:bbbb"]`
	sum := sha256.Sum256([]byte(layers + "\n"))
	file := func(name string) string { return filepath.Join(dir, name) }
	read := func(name string) string {
		data, _ := os.ReadFile(file(name))
		return strings.TrimSpace(string(data))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	type leg struct {
		name string
		cmd  *exec.Cmd
		out  strings.Builder
	}
	legs := []*leg{{name: "a"}, {name: "b"}}
	for _, l := range legs {
		for _, f := range []string{l.name + ".env", l.name + ".out"} {
			require.NoError(t, os.WriteFile(file(f), nil, 0o644))
		}
		l.cmd = exec.CommandContext(ctx, "bash", "-e", stepFile)
		l.cmd.Env = append(os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FAKE_DOCKER_STATE="+state,
			"FAKE_DOCKER_REAL="+realDocker,
			"HOME="+dir, "DOCKER_CONFIG=", "DOCKER_CONTEXT=", "DOCKER_HOST=",
			"FAKE_IMAGE_ID=sha256:1111",
			"FAKE_LAYERS="+layers,
			"RUNNER_TEMP="+tmp,
			"IT_REGISTRY=registry.invalid:5000",
			"IT_IMAGE_TAG=1111",
			"IT_IMAGE=go-trusted-platform-it:content",
			"IT_IMAGE_IDENTITY="+hex.EncodeToString(sum[:]),
			"REGISTRY_USER=", "REGISTRY_PASSWORD=",
			"IT_LEASE=lease-"+l.name,
			"GITHUB_ENV="+file(l.name+".env"),
			"GITHUB_OUTPUT="+file(l.name+".out"),
		)
		l.cmd.Stdout, l.cmd.Stderr = &l.out, &l.out
	}
	// With Stdout and Stderr the same writer, exec writes it from one
	// goroutine at a time.
	for _, l := range legs {
		require.NoError(t, l.cmd.Start())
	}
	errs := make([]error, len(legs))
	for i, l := range legs {
		errs[i] = l.cmd.Wait()
	}
	require.NoError(t, ctx.Err(), "the legs did not end within 60 s:\nA:\n%s\nB:\n%s", legs[0].out.String(), legs[1].out.String())
	for i, l := range legs {
		require.NoError(t, errs[i], "leg %s:\n%s", l.name, l.out.String())
		require.Contains(t, read(l.name+".out"), "leased=true", "leg %s:\n%s", l.name, l.out.String())
	}
	pulls, _ := os.ReadFile(filepath.Join(state, "pull-context"))
	require.Equal(t, 1, strings.Count(string(pulls), "\n"),
		"two overlapping legs on one daemon pulled more than once:\nA:\n%s\nB:\n%s", legs[0].out.String(), legs[1].out.String())
	require.FileExists(t, filepath.Join(state, "pull-lock-contended"),
		"the other leg never contended for the pull lock held across the pull:\nA:\n%s\nB:\n%s", legs[0].out.String(), legs[1].out.String())
}

// Containerd fails a pull that races another on its ref lock with errors a
// second attempt clears; the step retries those, at most 3 attempts, and
// falls back to the leg's build on any other error at once.
func TestCIRegistryPullRetriesTransientContainerdErrors(t *testing.T) {
	pull := ciStepRun(t, ciLegJob, "pull")
	load := ciStepRun(t, ciLegJob, "Load the integration image")
	const lease = `failed to prepare extraction snapshot "extract-1": lease does not exist: not found`
	t.Run("lease does not exist once", func(t *testing.T) {
		// The Load step runs only when the pull leased no image.
		r := runRegistrySteps(t, nil, []string{"FAKE_PULL_ERRS=" + lease}, pull)
		require.NoError(t, r.err, r.log)
		require.Equal(t, 2, strings.Count(r.read("pull-context")+"\n", "\n"), "pull attempts:\n%s", r.log)
		require.Equal(t, "5", r.read("sleeps"), r.log)
		require.Contains(t, r.log, lease, "the pull's output is not in the log:\n%s", r.log)
		require.Contains(t, r.output, "leased=true", r.log)
		require.Contains(t, r.env, "IT_LEASE_ID=sha256:1111\n", r.log)
		require.NotContains(t, r.log, "building this leg's image", r.log)
	})
	for name, tc := range map[string]struct {
		errs     string
		attempts int
		sleeps   string
	}{
		"transient every attempt": {errs: "failed to extract layer sha256:aaaa;failed to commit snapshot extract-2;failed to cleanup extract", attempts: 3, sleeps: "5\n15"},
		"unrelated error":         {errs: "manifest unknown", attempts: 1},
	} {
		t.Run(name, func(t *testing.T) {
			r := runRegistrySteps(t, nil, []string{"FAKE_PULL_ERRS=" + tc.errs}, pull, load)
			require.NoError(t, r.err, r.log)
			require.Equal(t, tc.attempts, strings.Count(r.read("pull-context")+"\n", "\n"), "pull attempts:\n%s", r.log)
			require.Equal(t, tc.sleeps, r.read("sleeps"), r.log)
			require.NotContains(t, r.output, "leased=true", r.log)
			require.Contains(t, r.log, "::warning::pulling "+"registry.invalid:5000/go-trusted-platform/it-image:1111 from the LAN registry failed; building this leg's image", r.log)
			require.Equal(t, "go-trusted-platform-it:leg-build", r.read("built"), "the Load step's fallback build:\n%s", r.log)
		})
	}
}

// reapedCacheLock is image-lock.sh for a leg whose daemon also runs
// scripts/reap-stale-ci-stacks.sh: the reaper holds the global image lock
// just before the leg's first turn on it, and removes the cached registry
// reference, old and unleased, as it does under that lock.
const reapedCacheLock = `image_lock() {
  echo "${1:-}" >> "$FAKE_DOCKER_STATE/lock-names"
  if [ "${1:-}" = go-trusted-platform-ci-image-lock ] && [ ! -e "$FAKE_DOCKER_STATE/reaped" ]; then
    : > "$FAKE_DOCKER_STATE/reaped"
    docker rmi "$IT_REGISTRY/go-trusted-platform/it-image:$IT_IMAGE_TAG" >/dev/null 2>&1 || true
  fi
  return 0
}
image_unlock() { :; }
`

// Codex round 3 on #2386: a cache hit checked only under the pull lock can
// be reaped before the leg re-tags it under the global image lock, leaving
// no lease. The leg checks and leases a cache hit under the global image
// lock, and pulls again when the reference is gone.
func TestCIRegistryPullLeasesAReapedCacheHit(t *testing.T) {
	step := ciStepRun(t, ciLegJob, "pull")
	r := runRegistrySteps(t, func(home string) {
		dir := filepath.Dir(home)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "runner-temp", "image-lock.sh"), []byte(reapedCacheLock), 0o644))
		cached := filepath.Join(dir, "state", "tags", "registry.invalid_5000_go-trusted-platform_it-image_1111")
		require.NoError(t, os.WriteFile(cached, []byte("sha256:1111\n"), 0o644))
	}, nil, step)
	require.NoError(t, r.err, r.log)
	require.FileExists(t, filepath.Join(r.state, "reaped"), "the reaper never ran:\n%s", r.log)
	require.Contains(t, r.output, "leased=true", "a reaped cache hit left the leg with no lease:\n%s", r.log)
	require.Contains(t, r.env, "IT_LEASE_ID=sha256:1111\n", r.log)
	require.Equal(t, "sha256:1111", r.read(filepath.Join("containers", "lease-leg")), "the lease is on the pulled image:\n%s", r.log)
	pulls, _ := os.ReadFile(filepath.Join(r.state, "pull-context"))
	require.Equal(t, 1, strings.Count(string(pulls), "\n"), "the leg pulls the reaped reference once:\n%s", r.log)
}
