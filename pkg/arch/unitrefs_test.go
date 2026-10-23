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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// DeadUnitReferenceError is one systemd unit directive in configs/os that
// names a project-owned binary or unit that does not exist in this repository.
type DeadUnitReferenceError struct {
	File      string
	Line      int
	Directive string
	Name      string
}

// Error renders the finding as a clickable `<file>:<line>` reference.
func (e DeadUnitReferenceError) Error() string {
	return fmt.Sprintf("%s:%d: %s names %s, which does not exist", e.File, e.Line, e.Directive, e.Name)
}

var (
	// unitExecRe matches an Exec* directive and captures the binary path.
	unitExecRe = regexp.MustCompile(`^(Exec[A-Za-z]*)=[-@+!:]*(\S+)`)

	// unitDependencyRe matches a unit dependency or ordering directive and
	// captures its space separated unit list.
	unitDependencyRe = regexp.MustCompile(`^(Requires|Requisite|Wants|BindsTo|PartOf|After|Before)=(.*)$`)
)

// isProjectUnitName reports whether a binary or unit is owned by this
// repository, as opposed to the distribution (systemd-networkd, /bin/sh).
func isProjectUnitName(name string) bool {
	return strings.HasPrefix(name, "platform") || strings.HasPrefix(name, "trusted-platform")
}

// scanUnitReferences reports every Exec* binary and every unit dependency in
// one systemd unit file that is project-owned but missing. binaryExists and
// unitExists take a bare name (`platformd`, `platformd.service`).
func scanUnitReferences(file, unit string, binaryExists, unitExists func(name string) bool) []DeadUnitReferenceError {
	var findings []DeadUnitReferenceError
	for i, raw := range strings.Split(unit, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if m := unitExecRe.FindStringSubmatch(line); m != nil {
			bin := path.Base(m[2])
			if isProjectUnitName(bin) && !binaryExists(bin) {
				findings = append(findings, DeadUnitReferenceError{File: file, Line: i + 1, Directive: m[1], Name: bin})
			}
			continue
		}
		if m := unitDependencyRe.FindStringSubmatch(line); m != nil {
			for _, ref := range strings.Fields(m[2]) {
				if strings.HasSuffix(ref, ".service") && isProjectUnitName(ref) && !unitExists(ref) {
					findings = append(findings, DeadUnitReferenceError{File: file, Line: i + 1, Directive: m[1], Name: ref})
				}
			}
		}
	}
	return findings
}

// TestSystemdUnitsReferenceExistingBinaries asserts that no unit under
// configs/os starts a project binary, or depends on a project unit, that this
// repository does not build or ship. The platform-api.service unit started
// /usr/sbin/platform-api, a binary with no cmd/ directory, and
// trusted-platform-network.service required that unit (#411).
func TestSystemdUnitsReferenceExistingBinaries(t *testing.T) {
	root := repoRoot(t)
	osDir := filepath.Join(root, "configs", "os")
	units, err := filepath.Glob(filepath.Join(osDir, "*.service"))
	require.NoError(t, err)
	require.NotEmpty(t, units, "no systemd units found under configs/os")

	binaryExists := func(name string) bool {
		if info, statErr := os.Stat(filepath.Join(root, "cmd", name)); statErr == nil && info.IsDir() {
			return true
		}
		_, statErr := os.Stat(filepath.Join(osDir, name))
		return statErr == nil
	}
	unitExists := func(name string) bool {
		_, statErr := os.Stat(filepath.Join(osDir, name))
		return statErr == nil
	}

	var lines []string
	for _, unitPath := range units {
		data, readErr := os.ReadFile(unitPath)
		require.NoError(t, readErr)
		rel := "configs/os/" + filepath.Base(unitPath)
		for _, f := range scanUnitReferences(rel, string(data), binaryExists, unitExists) {
			lines = append(lines, f.Error())
		}
	}
	require.Empty(t, lines,
		"these systemd units reference project binaries or units that do not exist. "+
			"Repoint them at what ships, or delete the unit:\n%s", strings.Join(lines, "\n"))
}

const unitRefsFixture = `# Requires=platform-ghost.service in a comment is ignored
[Unit]
After=network.target systemd-networkd.service platformd.service
Requires=platform-api.service
Wants=trusted-platform-network.service

[Service]
ExecStart=/usr/sbin/platform-api --port=8443
ExecStartPre=-/bin/sh -c true
ExecStop=/usr/local/bin/platformd stop
`

// TestScanUnitReferencesFindsMissing is the positive control: a missing
// project unit and a missing project binary are reported at their line, and
// distribution units, shells and existing project names are not.
func TestScanUnitReferencesFindsMissing(t *testing.T) {
	exists := func(name string) bool { return name == "platformd" || name == "platformd.service" }

	findings := scanUnitReferences("fixture.service", unitRefsFixture, exists, exists)

	require.Equal(t, []DeadUnitReferenceError{
		{File: "fixture.service", Line: 4, Directive: "Requires", Name: "platform-api.service"},
		{File: "fixture.service", Line: 5, Directive: "Wants", Name: "trusted-platform-network.service"},
		{File: "fixture.service", Line: 8, Directive: "ExecStart", Name: "platform-api"},
	}, findings)
	require.Equal(t, "fixture.service:4: Requires names platform-api.service, which does not exist",
		findings[0].Error())
}

// TestScanUnitReferencesAcceptsExistingAndEmpty is the negative control:
// nothing is reported when every project name exists, and empty or
// comment-only input yields no findings.
func TestScanUnitReferencesAcceptsExistingAndEmpty(t *testing.T) {
	always := func(string) bool { return true }
	never := func(string) bool { return false }

	require.Empty(t, scanUnitReferences("fixture.service", unitRefsFixture, always, always))
	require.Empty(t, scanUnitReferences("fixture.service", "", never, never))
	require.Empty(t, scanUnitReferences("fixture.service", "# ExecStart=/usr/sbin/platform-api\n", never, never))
	require.Empty(t, scanUnitReferences("fixture.service", "After=systemd-networkd.service\nExecStart=/bin/true\n", never, never))
}
