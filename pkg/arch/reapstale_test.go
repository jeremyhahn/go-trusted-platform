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
  "network ls" | "volume ls") cat "$s/${1}s"; exit 0 ;;
  "network inspect" | "volume inspect")
    out=$4
    while IFS=$'\t' read -r expr val; do out=${out//"{{$expr}}"/"$val"}; done < "$s/$1/${!#}"
    case $out in *"{{"*) echo "fake docker: template: cannot render $out" >&2; exit 64 ;; esac
    printf '%s\n' "$out" ;;
  "network rm" | "volume rm")
    [ -e "$s/rm-fails/$3" ] && { echo "$1 $3 has active endpoints" >&2; exit 1; }
    echo "$1 rm $3" >> "$s/removed"; exit 0 ;;
  *) echo "fake docker: unexpected call: $*" >&2; exit 64 ;;
esac
`

// reapObject is one network or volume in the fixture.
type reapObject struct {
	name    string
	project string
	age     time.Duration
	users   []string
	rmFails bool
}

// reapFixture is the Docker host the fake answers for.
type reapFixture struct {
	networks []reapObject
	volumes  []reapObject
	psFails  bool
}

// write lays the fixture out in dir as fakeDocker reads it.
func (fx reapFixture) write(t *testing.T, dir string) {
	t.Helper()
	now := time.Now().UTC()
	for _, sub := range []string{"network", "volume", "users", "rm-fails"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	put := func(rel, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644))
	}
	list := func(kind string, objs []reapObject, inspect func(reapObject) map[string]string) {
		var names strings.Builder
		for _, o := range objs {
			names.WriteString(o.name + "\n")
			var fields strings.Builder
			for expr, val := range inspect(o) {
				fields.WriteString(expr + "\t" + val + "\n")
			}
			put(filepath.Join(kind, o.name), fields.String())
			if len(o.users) > 0 {
				put(filepath.Join("users", kind+"-"+o.name), strings.Join(o.users, "\n")+"\n")
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
	list("network", fx.networks, func(o reapObject) map[string]string {
		created := now.Add(-o.age)
		return map[string]string{
			".Name":                                  o.name,
			".Created":                               created.String(),
			`.Created.Format "` + time.RFC3339 + `"`: created.Format(time.RFC3339),
			project:                                  o.project,
		}
	})
	list("volume", fx.volumes, func(o reapObject) map[string]string {
		return map[string]string{
			".CreatedAt": now.Add(-o.age).Format(time.RFC3339),
			project:      o.project,
		}
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
