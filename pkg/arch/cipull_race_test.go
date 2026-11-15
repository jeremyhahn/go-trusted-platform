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
  else echo "Error response from daemon: No such image: $1" >&2; return 1; fi
}
case "$1" in
  login) cat >/dev/null; exit 0 ;;
  push) resolve "$2" >/dev/null || exit 1; echo "$2" >> "$s/pushed" ;;
  pull) echo "$FAKE_IMAGE_ID" > "$s/tags/$(enc "$2")" ;;
  tag) id=$(resolve "$2") || exit 1; echo "$id" > "$s/tags/$(enc "$3")" ;;
  rmi) rm "$s/tags/$(enc "$2")" 2>/dev/null || exit 1 ;;
  image)
    [ "$2" = inspect ] && [ "$3" = -f ] || { echo "fake docker: $*" >&2; exit 2; }
    id=$(resolve "$5") || exit 1
    case "$4" in
      '{{.Id}}') echo "$id" ;;
      '{{json .RootFS.Layers}}') echo "$FAKE_LAYERS" ;;
      *) echo "fake docker: $*" >&2; exit 2 ;;
    esac ;;
  create)
    [ "$2 $3 $4" = "--pull never --name" ] || { echo "fake docker: $*" >&2; exit 2; }
    resolve "$6" >/dev/null || exit 1
    touch "$s/containers/$5" ;;
  container) rm -f "$s/containers/$3" ;;
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
}

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
	ref := "image_ref=registry.invalid:5000/go-trusted-platform/it-image:1111"
	require.Equal(t, ref, read("a.out"))
	require.Equal(t, ref, read("b.out"))
	pushed, err := os.ReadFile(filepath.Join(state, "pushed"))
	require.NoError(t, err)
	pushedRef := strings.TrimPrefix(ref, "image_ref=")
	require.Equal(t, []string{pushedRef, pushedRef}, strings.Fields(string(pushed)), "both producers push")
	// The per-job Docker configs are gone with their jobs.
	left, err := filepath.Glob(filepath.Join(tmp, "docker-config.*"))
	require.NoError(t, err)
	require.Empty(t, left)
}
