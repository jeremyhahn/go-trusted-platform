// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// deliberatelyUnreached names every package that contains _test.go files and is
// deliberately NOT run by `make test`, with the reason.
//
// These are the hardware/root/daemon cases the Makefile's TEST_EXCLUDE comment
// already records: they need a TPM, cryptsetup, an OCI runtime, CAP_NET_ADMIN,
// or a running platformd, and are covered by `make integration-test` instead.
//
// THIS LIST MAY ONLY SHRINK. A package added here needs a reason that survives
// review; a package that stops needing its dependency comes off it.
var deliberatelyUnreached = map[string]string{
	"pkg/api/grpc":                    "gRPC server harness; covered by integration",
	"pkg/app":                         "needs a running platformd (re-added via TEST_UNIT_PKGS)",
	"pkg/cli":                         "needs a running platformd",
	"pkg/cli/commands":                "needs a running platformd; the SUBpackages are reached (#319)",
	"pkg/compute":                     "needs an OCI runtime",
	"pkg/compute/podman":              "needs an OCI runtime",
	"pkg/daemon/commands":             "needs a running platformd (re-added via TEST_UNIT_PKGS)",
	"pkg/device/dao":                  "datastore harness; covered by integration",
	"pkg/dns":                         "needs a running platformd (re-added via TEST_UNIT_PKGS)",
	"pkg/dns/dao":                     "datastore harness; covered by integration",
	"pkg/firstboot":                   "needs root and real block devices",
	"pkg/initrd":                      "static initramfs build; covered by integration",
	"pkg/installer":                   "needs root and real block devices",
	"pkg/installer/alpine":            "needs root and real block devices",
	"pkg/ipxe":                        "needs a bound TFTP/HTTP listener",
	"pkg/iso":                         "needs cpio/zstd/grub",
	"pkg/platform":                    "needs a TPM",
	"pkg/platform/system":             "needs root",
	"pkg/qemu":                        "needs QEMU",
	"pkg/sdn/gateway/commands":        "needs a running gatewayd",
	"pkg/sdn/netlink":                 "needs CAP_NET_ADMIN",
	"pkg/store/datastore":             "datastore harness; covered by integration",
	"pkg/storage/luks":                "needs cryptsetup",
	"pkg/swtpm":                       "needs swtpm",
	"pkg/testenv":                     "test scaffolding, not a unit under test",
	"pkg/uefi/firmware":               "needs a TPM",
	"pkg/uki":                         "needs sbsign/objcopy",
	"pkg/vtpm":                        "needs a TPM",
	"pkg/webservice":                  "needs a running platformd",
	"pkg/webservice/v1":               "needs a running platformd (re-added via TEST_UNIT_PKGS)",
	"pkg/webservice/v1/rest/platform": "needs a running platformd",
	"pkg/webservice/v1/test":          "test scaffolding, not a unit under test",
	"pkg/webservice/v1/webauthn":      "needs a running platformd",
	"pkg/boot/commands":               "needs root",
}

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}

// makeVar extracts a simple `NAME := value` assignment from the Makefile.
func makeVar(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	require.NoError(t, err)
	re := regexp.MustCompile(`(?m)^` + name + `\s*:=\s*(.*)$`)
	m := re.FindStringSubmatch(string(data))
	require.Len(t, m, 2, "%s not found in Makefile", name)
	// Recipes escape `$` as `$$`; the shell sees a single `$`.
	return strings.ReplaceAll(m[1], "$$", "$")
}

// TestEveryTestBearingPackageIsReached asserts that a package containing
// _test.go files is either discovered by `make test` or named in
// deliberatelyUnreached with a reason.
//
// This exists because TEST_EXCLUDE is a grep -E alternation, so an entry
// missing its `$` anchor is a SUBSTRING match that silently drops every
// subpackage beneath it. `pkg/cli/commands` was unanchored and took 31
// packages and 190 test files with it (#319) — and TEST_UNIT_PKGS, which was
// added to fix the previous instance of exactly this (#34), re-added two of
// them and thereby hid the other 31.
//
// Naming packages in TEST_UNIT_PKGS fixes an instance. Only this test closes
// the mechanism.
func TestEveryTestBearingPackageIsReached(t *testing.T) {
	root := repoRoot(t)
	excludeRe, err := regexp.Compile(makeVar(t, root, "TEST_EXCLUDE"))
	require.NoError(t, err, "TEST_EXCLUDE must be a valid regexp")

	unitPkgs := map[string]bool{}
	for _, p := range strings.Fields(makeVar(t, root, "TEST_UNIT_PKGS")) {
		unitPkgs[strings.Trim(p, "./")] = true
	}

	var unreached []string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "pkg/") && !strings.HasPrefix(rel, "cmd/") {
			return nil
		}
		matches, _ := filepath.Glob(filepath.Join(path, "*_test.go"))
		if len(matches) == 0 {
			return nil
		}
		if !excludeRe.MatchString(rel) || unitPkgs[rel] {
			return nil // discovered, or explicitly re-added
		}
		if _, ok := deliberatelyUnreached[rel]; !ok {
			unreached = append(unreached, rel)
		}
		return nil
	})
	require.NoError(t, walkErr)

	sort.Strings(unreached)
	require.Empty(t, unreached,
		"these packages contain tests that NO unit-test target runs. Either "+
			"anchor the TEST_EXCLUDE entry that swallowed them (check for a "+
			"missing `$$`), or add each to deliberatelyUnreached with the "+
			"dependency that keeps it out.")
}

// TestDeliberatelyUnreachedHasNoStaleEntries is the ratchet: once a package
// becomes reachable, its excuse must go, so the list cannot quietly stop
// shrinking.
func TestDeliberatelyUnreachedHasNoStaleEntries(t *testing.T) {
	root := repoRoot(t)
	excludeRe, err := regexp.Compile(makeVar(t, root, "TEST_EXCLUDE"))
	require.NoError(t, err)

	var nowReached, gone []string
	for pkg, reason := range deliberatelyUnreached {
		require.NotEmpty(t, reason, "%s needs a reason", pkg)
		if _, statErr := os.Stat(filepath.Join(root, pkg)); statErr != nil {
			gone = append(gone, pkg)
			continue
		}
		if !excludeRe.MatchString(pkg) {
			nowReached = append(nowReached, pkg)
		}
	}

	sort.Strings(nowReached)
	sort.Strings(gone)
	require.Empty(t, nowReached, "these are no longer excluded — delete their entries")
	require.Empty(t, gone, "these packages no longer exist — delete their entries")
}
