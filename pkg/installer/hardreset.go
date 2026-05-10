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
	"time"
)

// HardReset forces an immediate warm reboot of the system. Used after
// scheduling a UEFI PPI TPM ForceClear so firmware services the clear
// request during the next POST.
//
// The sequence is deliberate: we sync first so in-flight filesystem
// writes land, then try three progressively-nuclear mechanisms so we
// never fall into a shutdown-to-S5 path (seen on Supermicro X10 where
// `reboot -f` is translated into ACPI S5 instead of a CPU reset):
//
//  1. /proc/sysrq-trigger = b — the kernel's SysRq "immediate reboot"
//     command. Skips init, shutdown scripts, ACPI OFF; the CPU reset
//     vector fires directly. This is what we actually want on X10.
//
//  2. /proc/sysrq-trigger = c — SysRq "crash". Triggers a kernel panic
//     which (with panic=1 / panic_on_oops=1 on cmdline, or on most
//     modern distros by default) causes an immediate reset. Fallback
//     when the first doesn't fire because CONFIG_MAGIC_SYSRQ is compiled
//     but the kernel.sysrq sysctl disables the 'b' bit.
//
//  3. `reboot -f` — the userspace busybox reboot. Last resort because
//     on some platforms the initscripts intercept SIGINT and convert
//     to shutdown.
//
// We do NOT return from this function on success. The kernel either
// resets or crashes into a reset. If all three fail (impossible on a
// sane Linux), we return so the caller can log and exit.
func HardReset() {
	// Flush filesystem caches.
	_ = exec.Command("sync").Run()
	time.Sleep(100 * time.Millisecond)

	// 1. SysRq "b" — unconditional reset, bypasses init/ACPI.
	// Enable the full SysRq mask first in case the running kernel has
	// only a subset enabled (kernel.sysrq can be 0, 1, or a bitmask).
	_ = os.WriteFile("/proc/sys/kernel/sysrq", []byte("1"), 0o644)
	_ = os.WriteFile("/proc/sysrq-trigger", []byte("b"), 0o200)
	time.Sleep(2 * time.Second) // Give the kernel a beat to service the trigger.

	// 2. SysRq "c" — crash to trigger panic-on-oops reset.
	_ = os.WriteFile("/proc/sysrq-trigger", []byte("c"), 0o200)
	time.Sleep(2 * time.Second)

	// 3. busybox/openrc reboot. Some X10 firmware converts this into
	// ACPI S5 rather than a warm reset, which is exactly why we tried
	// SysRq first. Still worth attempting as a final fallback.
	_ = exec.Command("reboot", "-f").Run()
	time.Sleep(2 * time.Second)
	_ = exec.Command("reboot").Run()
}
