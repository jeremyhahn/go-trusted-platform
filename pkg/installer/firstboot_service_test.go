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

package installer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTPMFirstbootSealServiceDiskless runs the service's start() under
// /bin/sh against a diskless command line. It must succeed before the LUKS
// lookup: a diskless node has no rd.luks.uuid, and failing there every boot
// would report a sealing failure on a node with nothing to seal. The disk
// branch is the shared platformd_boot_model, covered by the iso tests.
func TestTPMFirstbootSealServiceDiskless(t *testing.T) {
	dir := t.TempDir()
	cmdline := filepath.Join(dir, "cmdline")
	require.NoError(t, os.WriteFile(cmdline,
		[]byte("platform_boot_model=diskless platform_roothash=1111 ro console=ttyS0\n"), 0o600))

	script := strings.ReplaceAll(tpmFirstbootSealService, "/proc/cmdline", cmdline)
	require.NotEqual(t, tpmFirstbootSealService, script, "the service must read the kernel command line")
	service := filepath.Join(dir, "tpm-firstboot-seal")
	require.NoError(t, os.WriteFile(service, []byte(script), 0o600))

	// OpenRC's helpers, stubbed: einfo and eerror print so the test sees
	// which branch ran, eend returns its status as OpenRC's does.
	stubs := `ebegin() { :; }; einfo() { echo "INFO $*"; }; ewarn() { :; }; ` +
		`eerror() { echo "ERROR $*"; }; eend() { return "$1"; }; `
	out, err := exec.Command("/bin/sh", "-c", stubs+`. "$0" && start`, service).CombinedOutput()
	require.NoError(t, err, "start() output: %s", out)
	assert.Contains(t, string(out), "INFO Diskless node: no LUKS root to seal")
	assert.NotContains(t, string(out), "ERROR")
}
