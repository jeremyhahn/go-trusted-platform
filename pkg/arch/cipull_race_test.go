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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
    echo "${FAKE_PULLED_ID:-$FAKE_IMAGE_ID}" > "$s/tags/$(enc "$2")" ;;
  tag) echo "$ctx" >> "$s/tag-context"; id=$(resolve "$2") || exit 1; echo "$id" > "$s/tags/$(enc "$3")" ;;
  rmi) rm "$s/tags/$(enc "$2")" 2>/dev/null || exit 1 ;;
  image)
    [ "$2" = inspect ] && [ "$3" = -f ] || { echo "fake docker: $*" >&2; exit 2; }
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
    echo "$id" > "$s/containers/$5" ;;
  container) rm -f "$s/containers/$3" ;;
  rm) rm -f "$s/containers/$2" ;;
  *) echo "fake docker: $*" >&2; exit 2 ;;
esac
`

// twoLegLock is the image lock both legs source. Leg B pulled first; its
// first image_lock waits while leg A, which pulled too, runs its whole pull
// step under the lock. Leg B then takes the lock.
const twoLegLock = `image_lock() {
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

// The fixture registry and the path:tag the image job's push step emits as
// image_ref for IT_LEASE_ID sha256:1111; a leg pulls the two joined.
const (
	ciFixtureRegistry  = "registry.invalid:5000"
	ciFixtureImagePath = "go-trusted-platform/it-image:1111"
	ciFixtureImageRef  = ciFixtureRegistry + "/" + ciFixtureImagePath
)

// runTwoLegPull runs the pull step as two legs on one cold daemon: both
// pulls succeed before either leg acquires the image lock, then leg A and
// leg B acquire it in turn.
func runTwoLegPull(t *testing.T, step string) (a, b pullLeg) {
	t.Helper()
	dir := t.TempDir()
	bin, state, tmp := filepath.Join(dir, "bin"), filepath.Join(dir, "state"), filepath.Join(dir, "runner-temp")
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
		"IT_IMAGE_REF=registry.example/go-trusted-platform-it:sha256-1111",
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
	out, err := cmd.CombinedOutput()
	b.rc, b.log = "0", string(out)
	if err != nil {
		b.rc = err.Error()
	}
	read := func(name string) string {
		data, _ := os.ReadFile(file(name))
		return strings.TrimSpace(string(data))
	}
	a = pullLeg{rc: read("a.rc"), output: read("a.out"), log: read("a.log")}
	b.output = read("b.out")
	data, _ := os.ReadFile(filepath.Join(state, "pulled"))
	b.pulled = strings.TrimSpace(string(data))
	return a, b
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

	a, b := runTwoLegPull(t, step)
	require.Equal(t, "0", a.rc, "leg A, first to take the lock:\n%s", a.log)
	require.Contains(t, a.output, "leased=true", "leg A:\n%s", a.log)
	require.Equal(t, "0", b.rc, "leg B, second to take the lock:\n%s", b.log)
	require.Contains(t, b.output, "leased=true", "leg B:\n%s", b.log)
	require.Equal(t, []string{ciFixtureImageRef, ciFixtureImageRef}, strings.Fields(b.pulled),
		"each leg pulls the registry-prefixed image path:\nA:\n%s\nB:\n%s", a.log, b.log)
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
	// The image_ref output carries no registry host (the runner drops a
	// secret-derived output); the push itself goes to the registry.
	ref := "image_ref=go-trusted-platform/it-image:1111"
	require.Equal(t, ref, read("a.out"))
	require.Equal(t, ref, read("b.out"))
	pushed, err := os.ReadFile(filepath.Join(state, "pushed"))
	require.NoError(t, err)
	pushedRef := "registry.invalid:5000/" + strings.TrimPrefix(ref, "image_ref=")
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
		"IT_REGISTRY=registry.invalid:5000",
		"IT_LEASE_ID=sha256:1111",
		"IT_IMAGE_REF=registry.invalid:5000/go-trusted-platform/it-image:1111",
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
// registry-prefixed path the push emitted as image_ref, and lease it.
func TestCIRegistryPullTakesThePushedReference(t *testing.T) {
	r := runRegistrySteps(t, nil, nil, ciStepRun(t, ciImageJob, "push"), ciStepRun(t, ciLegJob, "pull"))
	require.NoError(t, r.err, r.log)
	var path string
	for _, line := range strings.Split(r.output, "\n") {
		if v, ok := strings.CutPrefix(line, "image_ref="); ok {
			path = v
		}
	}
	require.NotEmpty(t, path, "the push step emits no image_ref:\n%s", r.log)
	require.Equal(t, ciFixtureRegistry+"/"+path, r.read("pulled"), "the pull step's reference:\n%s", r.log)
	require.Contains(t, r.output, "leased=true", r.log)
}
