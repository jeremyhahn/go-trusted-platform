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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The reaper's tests run scripts/reap-stale-ci-stacks.sh against a fake
// `docker` first on PATH, which answers from a fixture directory and records
// every removal. No Docker daemon is involved.

const (
	reaperScript = "scripts/reap-stale-ci-stacks.sh"
	reaperPrefix = "go-trusted-platform-ci-"
	// reaperMinAge is the script's default min-age: 3h05m.
	reaperMinAge = 11100 * time.Second
)

// fakeDocker answers the calls the reaper makes. The fixture directory holds
// networks and volumes (one id or name per line), network/<id> and
// volume/<name> (the inspect fields, one `<expression>\t<rendering>` per
// line), users/<kind>-<name> (the containers `ps --filter <kind>=<name>`
// lists), rm-fails/<name>, and ps-fails. Every successful removal is appended
// to removed. An inspect renders the -f template as Docker does, replacing
// each {{<expression>}} with its fixture rendering; an expression the fixture
// does not hold fails the call, so the script's templates are checked too.
const fakeDocker = `#!/usr/bin/env bash
s=$FAKE_DOCKER_STATE
case "$1 $2" in
  "ps -a") exit 0 ;;
  "ps -aq")
    [ -e "$s/ps-fails" ] && { echo "cannot connect to the Docker daemon" >&2; exit 1; }
    f=${4#*=}; kind=${4%%=*}
    [ -e "$s/users/$kind-$f" ] && cat "$s/users/$kind-$f"
    exit 0 ;;
  "network ls" | "volume ls" | "image ls") cat "$s/${1}s"; exit 0 ;;
  "network inspect" | "volume inspect" | "image inspect")
    out=$4
    while IFS=$'\t' read -r expr val; do out=${out//"{{$expr}}"/"$val"}; done < "$s/$1/${!#}"
    case $out in *"{{"*) echo "fake docker: template: cannot render $out" >&2; exit 64 ;; esac
    printf '%s\n' "$out" ;;
  "network rm" | "volume rm" | "image rm")
    [ -e "$s/rm-fails/$3" ] && { echo "$1 $3 has active endpoints" >&2; exit 1; }
    echo "$1 rm $3" >> "$s/removed"; exit 0 ;;
  *) echo "fake docker: unexpected call: $*" >&2; exit 64 ;;
esac
`

// reapObject is one network or volume in the fixture.
type reapObject struct {
	name    string
	project string
	// claim is a volume's ci.claim label: the <run id>-<attempt> it claims.
	claim   string
	age     time.Duration
	users   []string
	rmFails bool
	// inspectFails leaves the object listed but not inspectable.
	inspectFails bool
}

// reapFixture is the Docker host the fake answers for.
type reapFixture struct {
	networks []reapObject
	volumes  []reapObject
	// images are named by reference (repository:tag); project is unused.
	images  []reapObject
	psFails bool
}

// write lays the fixture out in dir as fakeDocker reads it.
func (fx reapFixture) write(t *testing.T, dir string) {
	t.Helper()
	now := time.Now().UTC()
	for _, sub := range []string{"network", "volume", "image", "users", "rm-fails"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	put := func(rel, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644))
	}
	// filter is the `docker ps --filter` key that finds a container using
	// one: the kind itself, but `ancestor` for an image.
	list := func(kind, filter string, objs []reapObject, inspect func(reapObject) map[string]string) {
		var names strings.Builder
		for _, o := range objs {
			names.WriteString(o.name + "\n")
			var fields strings.Builder
			for expr, val := range inspect(o) {
				fields.WriteString(expr + "\t" + val + "\n")
			}
			if !o.inspectFails {
				put(filepath.Join(kind, o.name), fields.String())
			}
			if len(o.users) > 0 {
				put(filepath.Join("users", filter+"-"+o.name), strings.Join(o.users, "\n")+"\n")
			}
			if o.rmFails {
				put(filepath.Join("rm-fails", o.name), "")
			}
		}
		put(kind+"s", names.String())
	}
	// What the daemon's templates render: a network's Created is a Go
	// time.Time, printed by its String method with spaces in it unless the
	// template formats it; a volume's CreatedAt is an RFC 3339 string.
	project := `index .Labels "com.docker.compose.project"`
	list("network", "network", fx.networks, func(o reapObject) map[string]string {
		created := now.Add(-o.age)
		return map[string]string{
			".Name":                                  o.name,
			".Created":                               created.String(),
			`.Created.Format "` + time.RFC3339 + `"`: created.Format(time.RFC3339),
			project:                                  o.project,
		}
	})
	list("volume", "volume", fx.volumes, func(o reapObject) map[string]string {
		return map[string]string{
			".CreatedAt":               now.Add(-o.age).Format(time.RFC3339),
			project:                    o.project,
			`index .Labels "ci.claim"`: o.claim,
		}
	})
	// An image's Created is an RFC 3339 string with nanoseconds.
	list("image", "ancestor", fx.images, func(o reapObject) map[string]string {
		return map[string]string{".Created": now.Add(-o.age).Format(time.RFC3339Nano)}
	})
	if fx.psFails {
		put("ps-fails", "")
	}
}

// runReaper runs the script against fx and returns its output, the removals
// the fake recorded, and the script's exit error.
func runReaper(t *testing.T, fx reapFixture, args []string, env ...string) (string, []string, error) {
	t.Helper()
	bin, state := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755))
	fx.write(t, state)

	cmd := exec.CommandContext(t.Context(), filepath.Join(repoRoot(t), reaperScript), args...)
	cmd.Env = append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_DOCKER_STATE=" + state,
	}, env...)
	out, runErr := cmd.CombinedOutput()

	var removed []string
	data, readErr := os.ReadFile(filepath.Join(state, "removed"))
	if readErr == nil {
		removed = strings.Fields(strings.ReplaceAll(string(data), " rm ", "-rm-"))
	} else {
		require.ErrorIs(t, readErr, os.ErrNotExist)
	}
	return string(out), removed, runErr
}

func TestReaperRemovesOnlyStaleUnusedComposeNetworksAndVolumes(t *testing.T) {
	stale := reaperMinAge + time.Hour
	fx := reapFixture{
		networks: []reapObject{
			{name: reaperPrefix + "65120-1_default", project: reaperPrefix + "65120-1", age: stale},
			{name: reaperPrefix + "65300-1_default", project: reaperPrefix + "65300-1", age: time.Minute},
			{name: reaperPrefix + "65270-1_default", project: reaperPrefix + "65270-1", age: stale, users: []string{"4f1c0e2a9b7d"}},
			{name: "other-repo-ci-1_default", project: "other-repo-ci-1", age: stale},
		},
		volumes: []reapObject{
			{name: reaperPrefix + "65120-1_data", project: reaperPrefix + "65120-1", age: stale},
			{name: reaperPrefix + "65270-1_data", project: reaperPrefix + "65270-1", age: stale, users: []string{"4f1c0e2a9b7d"}},
		},
	}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Equal(t, []string{
		"network-rm-" + reaperPrefix + "65120-1_default",
		"volume-rm-" + reaperPrefix + "65120-1_data",
	}, removed, out)
	require.Contains(t, out, "keep  network "+reaperPrefix+"65300-1_default (created within 11100s)")
	require.Contains(t, out, "keep  network "+reaperPrefix+"65270-1_default (a container uses it)")
	require.Contains(t, out, "keep  volume "+reaperPrefix+"65270-1_data (a container uses it)")
	require.NotContains(t, out, "other-repo-ci-1")
	require.Contains(t, out, "2 orphaned network(s) or volume(s) removed")
}

// The integration-image job's copy of a run's image is removed by no leg
// when every leg ran on another daemon, or when its artifact upload failed
// and no leg ran (#1146): the next job's reaper on that daemon removes it.
func TestReaperRemovesOnlyStaleUnusedImages(t *testing.T) {
	stale := reaperMinAge + time.Hour
	image := reaperPrefix + "it:"
	fx := reapFixture{
		images: []reapObject{
			{name: image + "68720-1-legs", age: stale},
			{name: image + "68790-1-legs", age: time.Minute},
			{name: image + "68750-1-legs", age: stale, users: []string{"9a2b7c4d1e0f"}},
			{name: image + "68740-1-image", age: stale, rmFails: true},
			{name: "other-repo-ci-it:68720-1-legs", age: stale},
		},
	}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Equal(t, []string{"image-rm-" + image + "68720-1-legs"}, removed, out)
	require.Contains(t, out, "keep  image "+image+"68790-1-legs (created within 11100s)")
	require.Contains(t, out, "keep  image "+image+"68750-1-legs (a container uses it)")
	require.Contains(t, out, "warn  image "+image+"68740-1-image not removed")
	require.NotContains(t, out, "other-repo-ci-it")
	require.Contains(t, out, "reaper: 1 stale image(s) and 0 expired claim(s) removed for prefix '"+reaperPrefix+"'")
}

// The window #1146's review found: a job tags (or loads) its image and only
// then creates the lease that names it, and a warm build cache returns an
// image whose Created is past the min-age. The snapshot below is a reaper
// running inside that window: the tag is on the daemon, no container names
// it, Created is stale, and only the job's claim, created before the tag,
// is there. The claim keeps the tag, and every other tag of its run (a leg
// loading the integration-image job's tag). An expired claim is removed with
// the image it claimed.
func TestReaperKeepsTheImagesOfALiveClaimsRun(t *testing.T) {
	stale := reaperMinAge + time.Hour
	image := reaperPrefix + "it:"
	fx := reapFixture{
		volumes: []reapObject{
			{name: reaperPrefix + "68900-1-image-claim", claim: "68900-1", age: time.Minute},
			{name: reaperPrefix + "68902-1-leg3-claim", claim: "68902-1", age: time.Minute},
			{name: reaperPrefix + "68800-1-image-claim", claim: "68800-1", age: stale},
		},
		images: []reapObject{
			{name: image + "68900-1-image", age: stale},
			{name: image + "68902-1-legs", age: stale},
			{name: image + "68800-1-image", age: stale},
		},
	}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Equal(t, []string{
		"volume-rm-" + reaperPrefix + "68800-1-image-claim",
		"image-rm-" + image + "68800-1-image",
	}, removed, out)
	require.Contains(t, out, "keep  image "+image+"68900-1-image (run 68900-1 claims it)")
	require.Contains(t, out, "keep  image "+image+"68902-1-legs (run 68902-1 claims it)")
	require.Contains(t, out, "reaper: 1 stale image(s) and 1 expired claim(s) removed for prefix '"+reaperPrefix+"'")
}

// A claim the reaper cannot read might be live, so it keeps every image, and
// the claim itself, rather than guess which run the claim names.
func TestReaperKeepsEveryImageWhenAClaimCannotBeRead(t *testing.T) {
	stale := reaperMinAge + time.Hour
	image := reaperPrefix + "it:"
	fx := reapFixture{
		volumes: []reapObject{
			{name: reaperPrefix + "68910-1-image-claim", claim: "68910-1", age: stale, inspectFails: true},
		},
		images: []reapObject{{name: image + "68910-1-image", age: stale}},
	}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Empty(t, removed, out)
	require.Contains(t, out, "warn  claim "+reaperPrefix+"68910-1-image-claim: inspect failed, kept with every image")
	require.Contains(t, out, "reaper: 0 stale image(s) and 0 expired claim(s) removed")
}

func TestReaperHonoursTheMinAgeArgument(t *testing.T) {
	fx := reapFixture{networks: []reapObject{
		{name: reaperPrefix + "1-1_default", project: reaperPrefix + "1-1", age: 10 * time.Minute},
	}}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix, "300"})
	require.NoError(t, err, out)
	require.Equal(t, []string{"network-rm-" + reaperPrefix + "1-1_default"}, removed, out)
}

func TestReaperDryRunRemovesNothing(t *testing.T) {
	fx := reapFixture{networks: []reapObject{
		{name: reaperPrefix + "1-1_default", project: reaperPrefix + "1-1", age: reaperMinAge + time.Hour},
	}}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix}, "REAP_DRY_RUN=1")
	require.NoError(t, err, out)
	require.Empty(t, removed)
	require.Contains(t, out, "dry   docker network rm "+reaperPrefix+"1-1_default")
	require.Contains(t, out, "would be removed")
}

func TestReaperKeepsANetworkWhenItCannotListContainers(t *testing.T) {
	fx := reapFixture{
		networks: []reapObject{
			{name: reaperPrefix + "1-1_default", project: reaperPrefix + "1-1", age: reaperMinAge + time.Hour},
		},
		psFails: true,
	}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Empty(t, removed)
	require.Contains(t, out, "warn  network "+reaperPrefix+"1-1_default: cannot list its containers, kept")
}

func TestReaperReportsAFailedRemovalAndContinues(t *testing.T) {
	stale := reaperMinAge + time.Hour
	fx := reapFixture{networks: []reapObject{
		{name: reaperPrefix + "1-1_default", project: reaperPrefix + "1-1", age: stale, rmFails: true},
		{name: reaperPrefix + "2-1_default", project: reaperPrefix + "2-1", age: stale},
	}}

	out, removed, err := runReaper(t, fx, []string{reaperPrefix})
	require.NoError(t, err, out)
	require.Equal(t, []string{"network-rm-" + reaperPrefix + "2-1_default"}, removed, out)
	require.Contains(t, out, "warn  network "+reaperPrefix+"1-1_default not removed")
	require.Contains(t, out, "1 orphaned network(s) or volume(s) removed")
}

func TestReaperRejectsAnInvalidPrefix(t *testing.T) {
	out, removed, err := runReaper(t, reapFixture{}, []string{"bad prefix;"})
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), out)
	require.Equal(t, 2, exitErr.ExitCode())
	require.Empty(t, removed)
}
