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

package iso

import (
	"os/exec"
	"strings"
	"testing"
)

// The autoinstall wrapper is the far side of the seam #287 was about.
//
// pkg/installer returns an error, pkg/cli/commands/install/system.go turns it
// into ErrInstallationFailed, cmd/platformctl/main.go exits 1 — and THIS
// script is what reads that exit code and decides whether the machine reboots.
// The defect was a discontinuity between those layers: every layer implemented
// abort, and the first one never produced the code the rest were waiting for.
//
// So a test that only asserts "the installer returns an error" cannot close
// that issue. These assert the contract the installer's non-zero exit relies
// on: it is captured, it is branched on, and the failure branch does not
// reboot.

func autoinstallScriptFor(t *testing.T, afterInstall string) string {
	t.Helper()
	c := &Customizer{config: &PlatformISOConfig{
		Alpine:   AlpineConfig{Version: "3.22.2"},
		Platform: PlatformConfig{AfterInstallAction: afterInstall},
	}}
	return c.buildAutoinstallScript()
}

// failureBranch returns the text after the last `else` following the
// INSTALL_RESULT test — the branch that runs when the installer exits non-zero.
func failureBranch(t *testing.T, script string) string {
	t.Helper()
	const marker = "if [ $INSTALL_RESULT -eq 0 ]"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatalf("the script does not branch on INSTALL_RESULT; the installer's exit code is being ignored")
	}
	rest := script[start:]
	// The failure branch is the final else..fi of that conditional.
	elseIdx := strings.LastIndex(rest, "\nelse\n")
	if elseIdx < 0 {
		t.Fatalf("the INSTALL_RESULT conditional has no failure branch")
	}
	return rest[elseIdx:]
}

// TestAutoinstallScript_CapturesTheInstallerExitCode asserts the wrapper reads
// the installer's exit status at all. If this regresses, every abort added to
// pkg/installer becomes invisible again and the machine reboots regardless.
func TestAutoinstallScript_CapturesTheInstallerExitCode(t *testing.T) {
	for _, afterInstall := range []string{"reboot", "poweroff"} {
		t.Run(afterInstall, func(t *testing.T) {
			script := autoinstallScriptFor(t, afterInstall)

			for _, want := range []string{
				`INSTALL_RESULT=$?`,
				`if [ $INSTALL_RESULT -eq 0 ]`,
			} {
				if !strings.Contains(script, want) {
					t.Errorf("generated autoinstall script is missing %q — the installer's exit code would not reach the wrapper", want)
				}
			}
		})
	}
}

// TestAutoinstallScript_FailedInstallDoesNotReboot is the assertion that makes
// #287's fix meaningful end to end. A non-zero installer exit must leave the
// machine in the installer with its log, not reboot or power off a host whose
// ESP may have no bootloader on it.
func TestAutoinstallScript_FailedInstallDoesNotReboot(t *testing.T) {
	for _, afterInstall := range []string{"reboot", "poweroff"} {
		t.Run(afterInstall, func(t *testing.T) {
			branch := failureBranch(t, autoinstallScriptFor(t, afterInstall))

			// The configured after-install action belongs to the SUCCESS
			// branch only. Finding it here means a failed install disposes of
			// the machine before anyone can read why it failed.
			for _, forbidden := range []string{"\n    reboot", "\n    poweroff"} {
				if strings.Contains(branch, forbidden) {
					t.Errorf("the failure branch runs %q; a failed install must not reboot or power off the machine\nbranch:\n%s",
						strings.TrimSpace(forbidden), branch)
				}
			}

			// And it must actually fail: error() ends with exit 1.
			if !strings.Contains(branch, `error "Installation failed"`) {
				t.Errorf("the failure branch does not call error(); the wrapper would exit 0 on a failed install\nbranch:\n%s", branch)
			}
		})
	}
}

// The live environment runs the whole script or none of it: one syntax error
// anywhere and no install starts. An image with no security flag configured
// once emitted an empty if-body for them, which does not parse.
func TestAutoinstallScript_Parses(t *testing.T) {
	for name, security := range map[string]SecurityConfig{
		"no security flags": {},
		"every security flag": {
			FIPS:         true,
			Lockdown:     true,
			LockdownMode: "integrity",
			TPM:          TPMConfig{AutoUpgradeSeal: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Customizer{config: &PlatformISOConfig{
				Alpine:   AlpineConfig{Version: "3.22.2"},
				Platform: PlatformConfig{AfterInstallAction: "poweroff"},
				Security: security,
			}}

			out, err := exec.Command("sh", "-n", "-c", c.buildAutoinstallScript()).CombinedOutput()

			if err != nil {
				t.Fatalf("the autoinstall script does not parse: %v: %s", err, out)
			}
		})
	}
}

// TestAutoinstallScript_FailureBranchPreservesForensics guards the other half
// of what makes aborting acceptable. Stopping is only better than rebooting if
// the operator can find out why, and on an unattended install the console is
// often the only channel — so the log dump and the upload are part of the
// contract, not decoration.
func TestAutoinstallScript_FailureBranchPreservesForensics(t *testing.T) {
	branch := failureBranch(t, autoinstallScriptFor(t, "reboot"))

	for _, want := range []string{
		"cat /tmp/install.log",
		"upload_checkpoint install-failed",
		`upload_install_log_with_code "$INSTALL_RESULT"`,
	} {
		if !strings.Contains(branch, want) {
			t.Errorf("the failure branch no longer preserves %q; an aborted install would leave nothing to diagnose\nbranch:\n%s", want, branch)
		}
	}
}
