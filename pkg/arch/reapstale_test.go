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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The reaper's tests run scripts/reap-stale-ci-stacks.sh (the ci-template's
// reaper v5, ci-standard.md §9) against a fake `docker` first on PATH. The
// fake keeps the daemon's containers, images, networks and volumes in a state
// directory, so a removal, a lease and the image lock change what the
// reaper's later calls see. No Docker daemon is involved.
const (
	reaperScript = "scripts/reap-stale-ci-stacks.sh"
	reaperPrefix = "go-trusted-platform-ci-"
	reaperImage  = reaperPrefix + "it"
	reaperLock   = reaperPrefix + "image-lock"
)

// fakeDocker answers the calls reaper v5 and the repo's orphan sweep make.
// Rows are `|` separated: containers
// id|name|project|state|finished|created|ancestor|uses (uses: the networks
// and volumes it is attached to, comma separated), images
// ref|id|created|tagged, networks and volumes name|project|created. A file
// rm-fails-<key> fails that removal, inspect-fails-<ref> that image's,
// network's or volume's inspect, ps-ancestor-fails every ancestor listing. Removals go to
// `removed`, image lock events to `lock-log`; any other call exits 64.
const fakeDocker = `#!/usr/bin/env bash
set -u
st=$FAKE_DOCKER_STATE
unexpected() { echo "fake docker: unexpected call: $*" >&2; exit 64; }
rows() { [ ! -f "$st/$1" ] || cat "$st/$1"; }
drop() {
  local line
  [ -f "$st/$1" ] || return 0
  : > "$st/$1.new"
  while IFS= read -r line; do [ "${line%%|*}" = "$2" ] || echo "$line" >> "$st/$1.new"; done < "$st/$1"
  mv "$st/$1.new" "$st/$1"
}
fails() { [ -f "$st/$1" ]; }
case ${1:-} in
ps)
  all=$*; shift; quiet=0; filter=; format=
  while [ $# -gt 0 ]; do
    case $1 in
      -a) ;;
      -q | -aq) quiet=1 ;;
      --filter) filter=$2; shift ;;
      --format) format=$2; shift ;;
      *) unexpected "$all" ;;
    esac
    shift
  done
  case $filter in
    label=com.docker.compose.project | label=com.docker.compose.project=* | name=^*) ;;
    ancestor=*) ! fails ps-ancestor-fails || exit 1 ;;
    network=* | volume=*) ;;
    *) unexpected "$all" ;;
  esac
  rows containers | while IFS='|' read -r id name project state finished created ancestor uses; do
    case $filter in
      label=com.docker.compose.project) [ -n "$project" ] || continue ;;
      label=com.docker.compose.project=*) [ "$project" = "${filter#*project=}" ] || continue ;;
      name=^*) case $name in "${filter#name=^}"*) ;; *) continue ;; esac ;;
      ancestor=*) [ "$ancestor" = "${filter#ancestor=}" ] || continue ;;
      network=* | volume=*) case ",$uses," in *",${filter#*=},"*) ;; *) continue ;; esac ;;
    esac
    if [ "$quiet" = 1 ]; then
      echo "$id"
    elif [ "$format" = '{{.Label "com.docker.compose.project"}}' ]; then
      echo "$project"
    else
      echo "$id $name $project"
    fi
  done
  ;;
inspect)
  [ "${2:-}" = -f ] || unexpected "$*"
  found=
  while IFS='|' read -r id name project state finished created ancestor uses; do
    if [ "$id" = "$4" ] || [ "$name" = "$4" ]; then found=1; break; fi
  done < <(rows containers)
  [ -n "$found" ] || exit 1
  case $3 in
    '{{.State.Status}} {{.State.FinishedAt}} {{.Created}}') echo "$state $finished $created" ;;
    '{{.Id}} {{.Created}}') echo "$id $created" ;;
    *) unexpected "$*" ;;
  esac
  ;;
rm)
  shift
  [ "${1:-}" != -v ] || shift
  for id; do
    ! fails "rm-fails-$id" || { echo "fake docker: rm $id failed" >&2; exit 1; }
    name=$(rows containers | while IFS='|' read -r i n rest; do [ "$i" != "$id" ] || echo "$n"; done)
    drop containers "$id"
    case $name in
      *image-lock) echo "rm $name" >> "$st/lock-log" ;;
      *) echo "container-rm-$name" >> "$st/removed" ;;
    esac
  done
  ;;
create)
  [ "$2 $3 $4" = "--pull never --name" ] && [ "${7:-}" = true ] || unexpected "$*"
  name=$5 base=$6
  if rows containers | cut -d'|' -f2 | grep -qx -- "$name"; then
    echo "fake docker: the name $name is in use" >&2
    exit 1
  fi
  [ "$base" = "$(cat "$st/lockbase" 2>/dev/null)" ] || unexpected "$*"
  id="lock$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  echo "$id|$name||created||$(date -u +%Y-%m-%dT%H:%M:%SZ)|$base" >> "$st/containers"
  echo "create $name" >> "$st/lock-log"
  echo "$id"
  ;;
import)
  [ "${2:-}" = - ] || unexpected "$*"
  cat > /dev/null
  echo "$3" > "$st/lockbase"
  echo "import $3" >> "$st/lock-log"
  ;;
images)
  [ "${2:-}" = --filter ] && [ "${4:-}" = --format ] || unexpected "$*"
  repo=${3#reference=}
  rows images | while IFS='|' read -r ref rest; do [ "${ref%:*}" != "$repo" ] || echo "$ref"; done
  ;;
image)
  case ${2:-} in
  inspect)
    if [ "${3:-}" != -f ]; then
      [ "$3" = "$(cat "$st/lockbase" 2>/dev/null)" ]
      exit
    fi
    ! fails "inspect-fails-$5" || exit 1
    found=
    while IFS='|' read -r ref id created tagged; do
      if [ "$ref" = "$5" ]; then found=1; break; fi
    done < <(rows images)
    [ -n "$found" ] || exit 1
    case $4 in
      '{{.Id}} {{.Created}}') echo "$id $created" ;;
      '{{.Metadata.LastTagTime}}') echo "$tagged" ;;
      *) unexpected "$*" ;;
    esac
    ;;
  rm)
    ! fails "rm-fails-$3" || { echo "fake docker: conflict: $3 is in use" >&2; exit 1; }
    drop images "$3"
    echo "image-rm-$3" >> "$st/removed"
    ;;
  *) unexpected "$*" ;;
  esac
  ;;
network | volume)
  kind=$1
  case ${2:-} in
  ls)
    [ "$3 $4" = "-q --filter" ] || unexpected "$*"
    rows "${kind}s" | while IFS='|' read -r name project created; do
      case $5 in
        label=com.docker.compose.project) [ -z "$project" ] || echo "$name" ;;
        label=com.docker.compose.project=*) [ "$project" != "${5#label=com.docker.compose.project=}" ] || echo "$name" ;;
        *) unexpected "$*" ;;
      esac
    done
    ;;
  inspect)
    [ "${3:-}" = -f ] || unexpected "$*"
    ! fails "inspect-fails-$5" || exit 1
    found=
    while IFS='|' read -r name project created; do
      if [ "$name" = "$5" ]; then found=1; break; fi
    done < <(rows "${kind}s")
    [ -n "$found" ] || exit 1
    case "$kind $4" in
      'network {{.Name}} {{.Created.Format "2006-01-02T15:04:05Z07:00"}} {{index .Labels "com.docker.compose.project"}}') echo "$name $created $project" ;;
      'volume {{.CreatedAt}} {{index .Labels "com.docker.compose.project"}}') echo "$created $project" ;;
      *) unexpected "$*" ;;
    esac
    ;;
  rm)
    ! fails "rm-fails-$3" || { echo "fake docker: $kind rm $3 failed" >&2; exit 1; }
    drop "${kind}s" "$3"
    echo "$kind-rm-$3" >> "$st/removed"
    ;;
  *) unexpected "$*" ;;
  esac
  ;;
*) unexpected "$*" ;;
esac
`

// reapContainer is a container on the fake daemon. Age is how long ago an
// exited container finished, or a created one was created.
type reapContainer struct {
	name, project, state string
	age                  time.Duration
	// image is the ref of the fixture image the container runs on.
	image   string
	rmFails bool
	// uses names the networks and volumes the container is attached to.
	uses []string
}

// reapImage is one tag on the fake daemon. Images that share an id share
// their containers. A zero tagged is the never-tagged zero time.
type reapImage struct {
	ref, id         string
	created, tagged time.Duration
	inspectFails    bool
	rmFails         bool
}

// reapResource is a compose network or volume.
type reapResource struct {
	name, project         string
	age                   time.Duration
	rmFails, inspectFails bool
}

type reapFixture struct {
	containers        []reapContainer
	images            []reapImage
	networks, volumes []reapResource
	psAncestorFails   bool
}

func dockerTime(now time.Time, age time.Duration) string {
	return now.Add(-age).UTC().Format(time.RFC3339Nano)
}

// dockerTagTime is how `docker image inspect` prints Metadata.LastTagTime.
func dockerTagTime(now time.Time, age time.Duration) string {
	if age == 0 {
		return "0001-01-01 00:00:00 +0000 UTC"
	}
	return now.Add(-age).UTC().Format("2006-01-02 15:04:05.999999999 -0700 MST")
}

func (fx reapFixture) write(t *testing.T, dir string) {
	t.Helper()
	now := time.Now()
	ids := map[string]string{}
	var images []string
	for _, img := range fx.images {
		ids[img.ref] = img.id
		images = append(images, strings.Join([]string{img.ref, img.id, dockerTime(now, img.created), dockerTagTime(now, img.tagged)}, "|"))
		if img.inspectFails {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "inspect-fails-"+img.ref), nil, 0o644))
		}
		if img.rmFails {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "rm-fails-"+img.ref), nil, 0o644))
		}
	}
	var containers []string
	for i, c := range fx.containers {
		id := fmt.Sprintf("c%d", i)
		finished, created := "0001-01-01T00:00:00Z", dockerTime(now, c.age)
		if c.state == "exited" {
			finished, created = dockerTime(now, c.age), dockerTime(now, c.age+time.Hour)
		}
		containers = append(containers, strings.Join([]string{id, c.name, c.project, c.state, finished, created, ids[c.image], strings.Join(c.uses, ",")}, "|"))
		if c.rmFails {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "rm-fails-"+id), nil, 0o644))
		}
	}
	resources := func(rs []reapResource) []string {
		var rows []string
		for _, r := range rs {
			rows = append(rows, strings.Join([]string{r.name, r.project, dockerTime(now, r.age)}, "|"))
			if r.rmFails {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "rm-fails-"+r.name), nil, 0o644))
			}
			if r.inspectFails {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "inspect-fails-"+r.name), nil, 0o644))
			}
		}
		return rows
	}
	files := map[string][]string{
		"containers": containers,
		"images":     images,
		"networks":   resources(fx.networks),
		"volumes":    resources(fx.volumes),
	}
	for name, rows := range files {
		data := strings.Join(rows, "\n")
		if data != "" {
			data += "\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644))
	}
	if fx.psAncestorFails {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ps-ancestor-fails"), nil, 0o644))
	}
}

// reapRun is what one reaper run printed and did to the fake daemon.
type reapRun struct {
	out     string
	removed []string
	lockLog []string
	// left is the containers file after the run, one row a line.
	left string
}

// fileLines reads a state file's lines; a file the run never wrote is none.
func fileLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	return strings.Fields(strings.ReplaceAll(string(data), " ", "_"))
}

func runReaper(t *testing.T, fx reapFixture, args []string, env ...string) (reapRun, error) {
	t.Helper()
	bin, state := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755))
	fx.write(t, state)

	cmd := exec.Command("bash", append([]string{filepath.Join(repoRoot(t), reaperScript)}, args...)...)
	cmd.Env = append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_DOCKER_STATE=" + state,
		"HOME=" + state,
	}, env...)
	out, err := cmd.CombinedOutput()
	left, readErr := os.ReadFile(filepath.Join(state, "containers"))
	require.NoError(t, readErr)
	return reapRun{
		out:     string(out),
		removed: fileLines(t, filepath.Join(state, "removed")),
		lockLog: fileLines(t, filepath.Join(state, "lock-log")),
		left:    string(left),
	}, err
}

func runReaperOK(t *testing.T, fx reapFixture, args []string, env ...string) reapRun {
	t.Helper()
	run, err := runReaper(t, fx, args, env...)
	require.NoError(t, err, run.out)
	return run
}

var reaperArgs = []string{reaperPrefix}

func TestReaperRemovesAStaleUnusedImageUnderTheImageLock(t *testing.T) {
	run := runReaperOK(t, reapFixture{images: []reapImage{
		{ref: reaperImage + ":0a1b2c3d4e5f6071", id: "sha256:old", created: 3 * time.Hour},
	}}, reaperArgs)

	require.Equal(t, []string{"image-rm-" + reaperImage + ":0a1b2c3d4e5f6071"}, run.removed, run.out)
	require.Contains(t, run.out, "reap  image "+reaperImage+":0a1b2c3d4e5f6071")
	require.Contains(t, run.out, "reaper: 0 compose project(s) and 1 image(s) removed for prefix '"+reaperPrefix+"'")
	// The lock is taken before the listing and dropped at the end.
	require.Equal(t, []string{"import_" + reaperLock + ":base", "create_" + reaperLock, "rm_" + reaperLock}, run.lockLog)
	require.NotContains(t, run.left, reaperLock)
}

func TestReaperKeepsAnImageCreatedOrTaggedWithinTheImageMinAge(t *testing.T) {
	run := runReaperOK(t, reapFixture{images: []reapImage{
		{ref: reaperImage + ":fresh", id: "sha256:fresh", created: 10 * time.Minute},
		// A warm build cache hands back an old Created time; the tag is new.
		{ref: reaperImage + ":retagged", id: "sha256:retagged", created: 5 * time.Hour, tagged: 10 * time.Minute},
	}}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  image "+reaperImage+":fresh (created or tagged within 7200s)")
	require.Contains(t, run.out, "keep  image "+reaperImage+":retagged (created or tagged within 7200s)")
}

func TestReaperHonoursTheImageMinAgeVariable(t *testing.T) {
	fx := reapFixture{images: []reapImage{
		{ref: reaperImage + ":twenty", id: "sha256:twenty", created: 20 * time.Minute},
	}}

	run := runReaperOK(t, fx, reaperArgs, "REAP_IMAGE_MIN_AGE=600")
	require.Equal(t, []string{"image-rm-" + reaperImage + ":twenty"}, run.removed, run.out)

	run = runReaperOK(t, fx, reaperArgs)
	require.Empty(t, run.removed, run.out)
}

func TestReaperKeepsEveryTagOfAnImageAContainerUses(t *testing.T) {
	run := runReaperOK(t, reapFixture{
		images: []reapImage{
			{ref: reaperImage + ":leased", id: "sha256:shared", created: 5 * time.Hour},
			// Two trees that differ only in an ignored file tag one image twice.
			{ref: reaperImage + ":alias", id: "sha256:shared", created: 5 * time.Hour},
		},
		containers: []reapContainer{
			{name: reaperPrefix + "lease-71000-1-0a0b0c0d", state: "created", age: time.Minute, image: reaperImage + ":leased"},
		},
	}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  image "+reaperImage+":leased (in use: 1 container(s) on sha256:shared)")
	require.Contains(t, run.out, "keep  image "+reaperImage+":alias (in use: 1 container(s) on sha256:shared)")
}

func TestReaperRemovesTheImageOfADeadJobsStaleLease(t *testing.T) {
	lease := reaperPrefix + "lease-70000-1-0a0b0c0d"
	run := runReaperOK(t, reapFixture{
		images: []reapImage{{ref: reaperImage + ":orphan", id: "sha256:orphan", created: 6 * time.Hour}},
		containers: []reapContainer{
			{name: lease, state: "created", age: 4 * time.Hour, image: reaperImage + ":orphan"},
		},
	}, reaperArgs)

	require.Equal(t, []string{"container-rm-" + lease, "image-rm-" + reaperImage + ":orphan"}, run.removed, run.out)
	require.Contains(t, run.out, "reap  container "+lease)
}

func TestReaperKeepsAnImageItCannotCheck(t *testing.T) {
	run := runReaperOK(t, reapFixture{
		images: []reapImage{
			{ref: reaperImage + ":unlisted", id: "sha256:unlisted", created: 5 * time.Hour},
			{ref: reaperImage + ":uninspected", id: "sha256:uninspected", created: 5 * time.Hour, inspectFails: true},
		},
		psAncestorFails: true,
	}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  image "+reaperImage+":unlisted (could not list the containers on sha256:unlisted)")
	require.Contains(t, run.out, "keep  image "+reaperImage+":uninspected (docker image inspect gave no id)")
}

func TestReaperOnlyRemovesTheIntegrationImagesOfItsPrefix(t *testing.T) {
	run := runReaperOK(t, reapFixture{images: []reapImage{
		{ref: "other-ci-it:0a1b2c3d", id: "sha256:other", created: 9 * time.Hour},
		{ref: reaperPrefix + "toolchain:0a1b2c3d", id: "sha256:toolchain", created: 9 * time.Hour},
		{ref: "go-trusted-platform-it:local", id: "sha256:local", created: 9 * time.Hour},
		{ref: reaperImage + ":stale", id: "sha256:stale", created: 9 * time.Hour},
	}}, reaperArgs)

	require.Equal(t, []string{"image-rm-" + reaperImage + ":stale"}, run.removed, run.out)
}

func TestReaperWarnsWhenAnImageRemovalFails(t *testing.T) {
	run := runReaperOK(t, reapFixture{images: []reapImage{
		{ref: reaperImage + ":stuck", id: "sha256:stuck", created: 5 * time.Hour, rmFails: true},
		{ref: reaperImage + ":gone", id: "sha256:gone", created: 5 * time.Hour},
	}}, reaperArgs)

	require.Equal(t, []string{"image-rm-" + reaperImage + ":gone"}, run.removed, run.out)
	require.Contains(t, run.out, "warn  image "+reaperImage+":stuck not removed (in use?)")
	require.Contains(t, run.out, "and 1 image(s) removed")
}

func TestReaperKeepsEveryImageWhileAnotherHolderHasTheImageLock(t *testing.T) {
	run := runReaperOK(t, reapFixture{
		images: []reapImage{{ref: reaperImage + ":stale", id: "sha256:stale", created: 5 * time.Hour}},
		containers: []reapContainer{
			{name: reaperLock, state: "created", age: 30 * time.Second},
		},
	}, reaperArgs, "REAP_LOCK_WAIT=1")

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  every "+reaperImage+" image (the image lock was not free within 1s)")
	// The other holder's lock is never removed.
	require.Contains(t, run.left, "|"+reaperLock+"|")
	require.NotContains(t, run.lockLog, "rm_"+reaperLock)
}

func TestReaperRemovesADeadHoldersImageLock(t *testing.T) {
	run := runReaperOK(t, reapFixture{
		images: []reapImage{{ref: reaperImage + ":stale", id: "sha256:stale", created: 5 * time.Hour}},
		containers: []reapContainer{
			{name: reaperLock, state: "created", age: 11 * time.Minute},
		},
	}, reaperArgs)

	require.Equal(t, []string{"image-rm-" + reaperImage + ":stale"}, run.removed, run.out)
	require.Contains(t, run.out, "lock  removing the stale "+reaperLock)
	require.Equal(t, []string{"import_" + reaperLock + ":base", "rm_" + reaperLock, "create_" + reaperLock, "rm_" + reaperLock}, run.lockLog)
	require.NotContains(t, run.left, reaperLock)
}

func TestReaperReapsAStaleComposeProjectAndKeepsALiveOne(t *testing.T) {
	stale, live := reaperPrefix+"68000-1-leg1", reaperPrefix+"68001-1-leg2"
	run := runReaperOK(t, reapFixture{
		containers: []reapContainer{
			{name: stale + "-integration-1", project: stale, state: "exited", age: 4 * time.Hour},
			{name: stale + "-ovs-1", project: stale, state: "exited", age: 4 * time.Hour},
			{name: live + "-integration-1", project: live, state: "running"},
			{name: live + "-ovs-1", project: live, state: "exited", age: 4 * time.Hour},
			{name: "other-ci-1-integration-1", project: "other-ci-1", state: "exited", age: 9 * time.Hour},
		},
		networks: []reapResource{{name: stale + "_default", project: stale}, {name: live + "_default", project: live}},
		volumes:  []reapResource{{name: stale + "_state", project: stale}},
	}, reaperArgs)

	require.Equal(t, []string{
		"container-rm-" + stale + "-integration-1",
		"container-rm-" + stale + "-ovs-1",
		"network-rm-" + stale + "_default",
		"volume-rm-" + stale + "_state",
	}, run.removed, run.out)
	require.Contains(t, run.out, "reap  "+stale+": 2 container(s)")
	require.Contains(t, run.out, "keep  "+live+" (a container is live or stopped within 11100s)")
	require.Contains(t, run.out, "reaper: 1 compose project(s) and 0 image(s) removed")
}

func TestReaperHonoursTheMinAgeArgument(t *testing.T) {
	project := reaperPrefix + "69000-1-soak"
	fx := reapFixture{containers: []reapContainer{
		{name: project + "-integration-1", project: project, state: "exited", age: time.Hour},
	}}

	run := runReaperOK(t, fx, reaperArgs)
	require.Empty(t, run.removed, run.out)

	run = runReaperOK(t, fx, []string{reaperPrefix, "600"})
	require.Equal(t, []string{"container-rm-" + project + "-integration-1"}, run.removed, run.out)
}

func TestReaperReportsAFailedRemovalAndContinues(t *testing.T) {
	project := reaperPrefix + "68100-1-leg3"
	run := runReaperOK(t, reapFixture{
		containers: []reapContainer{
			{name: project + "-integration-1", project: project, state: "exited", age: 4 * time.Hour, rmFails: true},
		},
		networks: []reapResource{{name: project + "_default", project: project, rmFails: true}},
		volumes:  []reapResource{{name: project + "_state", project: project}},
	}, reaperArgs)

	require.Equal(t, []string{"volume-rm-" + project + "_state"}, run.removed, run.out)
	require.Contains(t, run.out, "warn  "+project+": container removal failed")
	require.Contains(t, run.out, "warn  "+project+": network "+project+"_default not removed")
}

func TestReaperDryRunRemovesNothing(t *testing.T) {
	project := reaperPrefix + "68200-1-leg4"
	run := runReaperOK(t, reapFixture{
		containers: []reapContainer{
			{name: project + "-integration-1", project: project, state: "exited", age: 4 * time.Hour},
		},
		images: []reapImage{{ref: reaperImage + ":stale", id: "sha256:stale", created: 5 * time.Hour}},
	}, reaperArgs, "REAP_DRY_RUN=1")

	require.Empty(t, run.removed, run.out)
	require.Empty(t, run.lockLog, "a dry run takes no image lock")
	require.Contains(t, run.out, "dry   docker rm -v c0")
	require.Contains(t, run.out, "dry   docker image rm "+reaperImage+":stale")
	require.Contains(t, run.out, "reaper: 1 compose project(s) and 1 image(s) would be removed for prefix '"+reaperPrefix+"'")
}

// orphans is a network and a volume of project, which has no containers,
// created age ago.
func orphans(project string, age time.Duration) (networks, volumes []reapResource) {
	return []reapResource{{name: project + "_default", project: project, age: age}},
		[]reapResource{{name: project + "_state", project: project, age: age}}
}

func TestReaperRemovesTheOrphanedNetworksAndVolumesOfAProjectWithoutContainers(t *testing.T) {
	project := reaperPrefix + "69000-1-leg1"
	networks, volumes := orphans(project, 4*time.Hour)
	run := runReaperOK(t, reapFixture{networks: networks, volumes: volumes}, reaperArgs)

	require.Equal(t, []string{"network-rm-" + project + "_default", "volume-rm-" + project + "_state"}, run.removed, run.out)
	require.Contains(t, run.out, "reap  network "+project+"_default (project "+project+" has no containers)")
	require.Contains(t, run.out, "reaper: 2 orphaned network(s) or volume(s) removed for prefix '"+reaperPrefix+"'")
}

func TestReaperKeepsOrphansCreatedWithinTheMinAge(t *testing.T) {
	project := reaperPrefix + "69100-1-leg2"
	networks, volumes := orphans(project, 10*time.Minute)
	run := runReaperOK(t, reapFixture{networks: networks, volumes: volumes}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  network "+project+"_default (created within 11100s)")
	require.Contains(t, run.out, "keep  volume "+project+"_state (created within 11100s)")
}

func TestReaperKeepsAnOrphanAContainerUses(t *testing.T) {
	project := reaperPrefix + "69200-1-leg3"
	networks, volumes := orphans(project, 4*time.Hour)
	run := runReaperOK(t, reapFixture{
		containers: []reapContainer{{name: "debug-shell", state: "running", age: time.Hour,
			uses: []string{project + "_default", project + "_state"}}},
		networks: networks,
		volumes:  volumes,
	}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  network "+project+"_default (a container uses it)")
	require.Contains(t, run.out, "keep  volume "+project+"_state (a container uses it)")
}

func TestReaperOnlySweepsOrphansOfItsPrefixAndOfProjectsWithoutContainers(t *testing.T) {
	foreign := "go-qrdb-ci-69300-1-leg1"
	live := reaperPrefix + "69300-1-leg4"
	foreignNets, foreignVols := orphans(foreign, 4*time.Hour)
	liveNets, liveVols := orphans(live, 4*time.Hour)
	run := runReaperOK(t, reapFixture{
		containers: []reapContainer{{name: live + "-integration-1", project: live, state: "running", age: time.Hour}},
		networks:   append(foreignNets, liveNets...),
		volumes:    append(foreignVols, liveVols...),
	}, reaperArgs)

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "keep  "+live+" (a container is live")
}

func TestReaperWarnsWhenAnOrphanCannotBeRemovedAndContinues(t *testing.T) {
	project := reaperPrefix + "69400-1-leg5"
	run := runReaperOK(t, reapFixture{
		networks: []reapResource{
			{name: project + "_a", project: project, age: 4 * time.Hour, rmFails: true},
			{name: project + "_b", project: project, age: 4 * time.Hour, inspectFails: true},
			{name: project + "_c", project: project, age: 4 * time.Hour},
		},
		volumes: []reapResource{
			{name: project + "_d", project: project, age: 4 * time.Hour, rmFails: true},
			{name: project + "_e", project: project, age: 4 * time.Hour, inspectFails: true},
			{name: project + "_f", project: project, age: 4 * time.Hour},
		},
	}, reaperArgs)

	require.Equal(t, []string{"network-rm-" + project + "_c", "volume-rm-" + project + "_f"}, run.removed, run.out)
	require.Contains(t, run.out, "warn  network "+project+"_a not removed")
	require.Contains(t, run.out, "warn  network "+project+"_b: inspect failed, kept")
	require.Contains(t, run.out, "warn  volume "+project+"_d not removed")
	require.Contains(t, run.out, "warn  volume "+project+"_e: inspect failed, kept")
}

func TestReaperDryRunRemovesNoOrphan(t *testing.T) {
	project := reaperPrefix + "69500-1-leg6"
	networks, volumes := orphans(project, 4*time.Hour)
	run := runReaperOK(t, reapFixture{networks: networks, volumes: volumes}, reaperArgs, "REAP_DRY_RUN=1")

	require.Empty(t, run.removed, run.out)
	require.Contains(t, run.out, "dry   docker network rm "+project+"_default")
	require.Contains(t, run.out, "dry   docker volume rm "+project+"_state")
	require.Contains(t, run.out, "reaper: 2 orphaned network(s) or volume(s) would be removed for prefix '"+reaperPrefix+"'")
}

func TestReaperRejectsInvalidArguments(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{name: "no prefix", args: nil, want: "usage:"},
		{name: "prefix outside the charset", args: []string{"bad prefix!"}, want: "usage:"},
		{name: "min-age not a number", args: []string{reaperPrefix, "3h"}, want: "min-age-seconds must be a number"},
		{name: "image min-age not a number", args: reaperArgs, env: []string{"REAP_IMAGE_MIN_AGE=2h"}, want: "REAP_IMAGE_MIN_AGE must be a number"},
		{name: "lock wait not a number", args: reaperArgs, env: []string{"REAP_LOCK_WAIT=-1"}, want: "REAP_LOCK_WAIT must be a number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run, err := runReaper(t, reapFixture{
				images: []reapImage{{ref: reaperImage + ":stale", id: "sha256:stale", created: 5 * time.Hour}},
			}, tc.args, tc.env...)
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 2, exitErr.ExitCode(), run.out)
			require.Contains(t, run.out, tc.want)
			require.Empty(t, run.removed)
		})
	}
}
