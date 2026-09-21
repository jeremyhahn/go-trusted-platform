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
	"fmt"
	"os"
	"path/filepath"
)

const (
	// kernelInstallHookRelPath is the kernel-install(8) drop-in plugin path on the
	// installed root. kernel-install runs every executable plugin in this
	// directory on kernel add/remove.
	kernelInstallHookRelPath = "etc/kernel/install.d/90-trusted-platform-uki.install"

	// apkCommitHookRelPath is the Alpine apk commit-hook bridge. apk does not
	// invoke kernel-install(8) drop-ins, so this hook fires the rebuild after an
	// `apk upgrade linux-*` transaction (apk runs commit_hooks.d scripts around
	// every commit).
	apkCommitHookRelPath = "etc/apk/commit_hooks.d/90-trusted-platform-uki"

	// kernelUpdateHookMode makes the hook scripts executable so kernel-install /
	// apk will run them.
	kernelUpdateHookMode = 0o755
)

// kernelInstallHookScript is the kernel-install(8) plugin. It contains only
// trigger glue: every rebuild / sign / verify / atomic-swap decision lives in
// the Go verb `platformctl install uki-rebuild`, which is unit-tested.
const kernelInstallHookScript = `#!/bin/sh
# 90-trusted-platform-uki.install - installed by go-trusted-platform.
#
# kernel-install(8) plugin. On kernel add/change it rebuilds and re-signs the
# Unified Kernel Image so the node stays bootable under enforced UEFI Secure
# Boot + CONFIG_MODULE_SIG_FORCE. All rebuild/sign/verify/atomic-swap logic
# lives in "platformctl install uki-rebuild" (Go); this drop-in is only the
# trigger glue.
#
# Plugin protocol: $1 = COMMAND (add|remove), $2 = KERNEL_VERSION.
set -eu

COMMAND="${1:-}"
KERNEL_VERSION="${2:-}"

PLATFORMCTL=/usr/bin/platformctl
[ -x "$PLATFORMCTL" ] || PLATFORMCTL=platformctl

case "$COMMAND" in
add|change)
	exec "$PLATFORMCTL" install uki-rebuild --kver "$KERNEL_VERSION"
	;;
*)
	exit 0
	;;
esac
`

// apkCommitHookScript bridges Alpine's apk to the UKI rebuild because apk does
// not invoke kernel-install(8) drop-ins. It is minimal trigger glue and gates on
// "did a newer kernel land?" so unrelated apk transactions do not rebuild.
const apkCommitHookScriptTemplate = `#!/bin/sh
# 90-trusted-platform-uki - installed by go-trusted-platform.
#
# Alpine's apk does not invoke kernel-install(8) drop-ins, so this commit hook
# bridges "apk add/upgrade linux-*" to the UKI rebuild. apk runs commit_hooks.d
# scripts with $1 = pre-commit | post-commit around each transaction. We act on
# post-commit, and only when the newest installed kernel is newer than the live
# UKI, so unrelated apk operations do not trigger a rebuild. All real logic lives
# in "platformctl install uki-rebuild" (Go).
set -eu

case "${1:-}" in
post-commit|post) ;;
*) exit 0 ;;
esac

UKI=%s
KVER=$(ls -1 /lib/modules 2>/dev/null | sort -V | tail -n1)
[ -n "$KVER" ] || exit 0

# Skip unless a freshly installed kernel is newer than the live UKI.
if [ -e "$UKI" ] && [ ! "/boot/vmlinuz-$KVER" -nt "$UKI" ] && [ ! "/lib/modules/$KVER" -nt "$UKI" ]; then
	exit 0
fi

PLATFORMCTL=/usr/bin/platformctl
[ -x "$PLATFORMCTL" ] || PLATFORMCTL=platformctl

"$PLATFORMCTL" install uki-rebuild --kver "$KVER" || logger -t trusted-platform "uki-rebuild failed for kernel $KVER"
`

// writeKernelUpdateHook writes the kernel-install(8) UKI-rebuild plugin onto the
// filesystem rooted at targetRoot and returns the absolute path written. It is
// factored out of installKernelUpdateHook so it is unit-testable against a temp
// directory without touching the host root.
func writeKernelUpdateHook(targetRoot string) (string, error) {
	return writeTargetHook(targetRoot, kernelInstallHookRelPath, kernelInstallHookScript)
}

// writeKernelUpdateAPKTrigger writes the Alpine apk commit-hook bridge onto the
// filesystem rooted at targetRoot, gating the rebuild on the live UKI at
// ukiPath, and returns the absolute path written.
func writeKernelUpdateAPKTrigger(targetRoot, ukiPath string) (string, error) {
	return writeTargetHook(targetRoot, apkCommitHookRelPath, fmt.Sprintf(apkCommitHookScriptTemplate, ukiPath))
}

// writeTargetHook writes content to targetRoot/relPath with the executable mode,
// creating parent directories. It chmods explicitly because WriteFile honours
// the umask, and kernel-install / apk require the hook to be executable.
func writeTargetHook(targetRoot, relPath, content string) (string, error) {
	dst := filepath.Join(targetRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", ErrUKIBuild("create kernel-update hook directory", err)
	}
	if err := os.WriteFile(dst, []byte(content), kernelUpdateHookMode); err != nil {
		return "", ErrUKIBuild("write kernel-update hook script", err)
	}
	if err := os.Chmod(dst, kernelUpdateHookMode); err != nil {
		return "", ErrUKIBuild("chmod kernel-update hook script", err)
	}
	return dst, nil
}

// installKernelUpdateHook installs the kernel-update UKI-rebuild hooks onto the
// installed system at /mnt. It is a no-op unless Secure Boot is enabled: an
// unsigned install boots fine after a kernel upgrade and needs no re-sign, so
// only Secure Boot installs get the rebuild trigger. It installs both the
// kernel-install(8) drop-in (for kernel-install-based dispatch) and the apk
// commit-hook bridge (so the rebuild also fires on Alpine, whose apk does not
// run kernel-install drop-ins).
func (i *installer) installKernelUpdateHook() error {
	if i.config.SecureBoot == nil || !i.config.SecureBoot.Enabled {
		i.logger.Info("[UKI-REBUILD] Secure Boot disabled — skipping kernel-update UKI rebuild hook")
		return nil
	}

	const mountPoint = "/mnt"

	hookPath, err := writeKernelUpdateHook(mountPoint)
	if err != nil {
		return err
	}
	i.logger.Info("[UKI-REBUILD] Installed kernel-install UKI rebuild hook", "path", hookPath)

	triggerPath, err := writeKernelUpdateAPKTrigger(mountPoint, i.ukiESPPath())
	if err != nil {
		return err
	}
	i.logger.Info("[UKI-REBUILD] Installed apk commit-hook bridge for UKI rebuild", "path", triggerPath)

	return nil
}
