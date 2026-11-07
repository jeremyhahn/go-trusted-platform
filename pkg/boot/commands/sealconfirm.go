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

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/boot/config"
	platforminitrd "github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/securewipe"
	"gopkg.in/yaml.v3"
)

// sealConfirmation is the second half of the firstboot seal lifecycle
// (#63). First boot seals the LUKS key to the TPM but keeps installer.luks
// — the container holding the plain key behind a documented constant
// password — because a seal that has never unsealed is not proven, and
// destroying the only fallback on the strength of an unproven seal would
// brick a node whose PCRs differ between the installer and production
// initramfs. The proof is the next boot's TPM-PCR unlock. This boot is
// that boot when the installer container was still on the ESP and the
// strategy that opened the root was TPM-PCR: the container is wiped here,
// before switch_root, by the process that has just closed it.
//
// Any other outcome preserves the container: a keyfile unlock means the
// seal did not work and firstboot's retry needs the key; a container this
// process did not mount is somebody else's to close.
type sealConfirmation struct {
	// efiPath is the mounted ESP.
	efiPath string
	// installerMounted is whether this process mounted installer.luks —
	// the only case in which it is also this process's to destroy.
	installerMounted bool
	// unlockedWith is the Name() of the strategy that unlocked the root.
	unlockedWith string
	// passes is the overwrite pass count (securewipe.PassesNIST when 0).
	passes int
	// wipe, sync and report are seams; nil means securewipe.File,
	// syscall.Sync and stderr.
	wipe   func(path string, passes int, report func(string)) error
	sync   func()
	report func(string)
}

// shouldConfirmSeal is the decision on its own: the container is destroyed
// only when it is ours and the seal has just proven itself.
func shouldConfirmSeal(installerMounted bool, unlockedWith string) bool {
	return installerMounted && unlockedWith == platforminitrd.StrategyNameTPMPCR
}

// run wipes the installer container when shouldConfirmSeal says so and
// reports whether it did. The container must already be closed (unmounted,
// LUKS locked, loop detached) by the caller.
func (c sealConfirmation) run() (bool, error) {
	report := c.report
	if report == nil {
		report = func(line string) { fmt.Fprintf(os.Stderr, "[BOOT] %s\n", line) }
	}
	wipe := c.wipe
	if wipe == nil {
		wipe = securewipe.File
	}
	installer := filepath.Join(c.efiPath, "tpm2", "installer.luks")

	if !c.installerMounted {
		return false, nil
	}
	if !shouldConfirmSeal(c.installerMounted, c.unlockedWith) {
		report(fmt.Sprintf("Unlocked with %s; installer.luks preserved until a TPM-PCR unlock proves the seal", c.unlockedWith))
		return false, nil
	}
	if _, err := os.Stat(installer); err != nil {
		return false, &WrappedError{Msg: "seal confirmed but the installer container is not where it was mounted from", Err: err}
	}

	passes := c.passes
	if passes < securewipe.PassesNIST {
		passes = securewipe.PassesNIST
	}
	report(fmt.Sprintf("Seal confirmed by TPM-PCR unlock: securely wiping installer.luks (%d passes)", passes))
	if err := wipe(installer, passes, report); err != nil {
		return false, &WrappedError{Msg: "wiping installer.luks after the confirmed seal", Err: err}
	}
	// The overwrite passes are fsynced by the wipe; the unlink is vfat
	// metadata that sits in the page cache until something flushes it.
	// A reset in the seconds before switch_root must not resurrect the
	// container, so the removal is made durable here, not left to the
	// unmount.
	sync := c.sync
	if sync == nil {
		sync = syscall.Sync
	}
	sync()
	report("installer.luks securely wiped; the firstboot seal lifecycle is complete")
	return true, nil
}

// loadSecureWipePassesFromConfig reads secure-wipe-passes from the platform
// config.yaml at the same locations loadSealPCRsFromConfig searches. An
// absent or zero value is the NIST single pass, so the confirmation never
// waits on a config field nobody sets.
func loadSecureWipePassesFromConfig() int {
	for _, path := range []string{
		filepath.Join(installerMountPoint, "etc", "trusted-platform", "config.yaml"),
		rootConfigPath,
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg config.BootConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if cfg.SecureWipePasses > 0 {
			return cfg.SecureWipePasses
		}
	}
	return securewipe.PassesNIST
}
