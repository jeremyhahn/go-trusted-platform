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

// platform-initrd is a minimal binary optimized for initramfs boot operations.
// It provides only the commands needed during early boot:
//   - boot: Unlock encrypted root filesystem using TPM-sealed keys
//   - recovery: Recovery mode for boot failures
//
// This binary is NOT user-facing. It is called by dracut hooks during
// the early boot process. After switch_root, firstboot provisioning
// runs via: platformctl firstboot
//
// Users should use platformctl for all operational commands.
package main

import (
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/boot/commands"
)

// SOL output policy
//
// The kernel cmdline (set by pkg/installer/installer.go) carries:
//
//	earlyprintk=efi,keep
//	earlycon=uart8250,io,0x3f8,115200n8
//	console=tty0 console=ttyS1,115200n8 console=ttyS0,115200n8
//
// On every supported BMC (Supermicro AST24xx/25xx, Dell iDRAC, HPE iLO,
// generic 8250) this routes everything written to the kernel console —
// which includes everything dracut and our binary write to fd 1 / fd 2 —
// straight onto the IPMI SOL channel. We do NOT need a userspace tee.
//
// HISTORY: an earlier revision installed a goroutine-based tee that
// mirrored os.Stderr to /dev/ttyS0 via a pipe + io.Copy. Under any flow
// control on the serial side (or even just a slow SOL session) the
// goroutine blocked on the device write, the pipe filled, and every
// subsequent fmt.Fprintf(os.Stderr, …) call in the binary deadlocked.
// platform-initrd then froze with no output, dracut timed out, and the
// system dropped to an emergency shell with "initrd: unlock failed". A
// "non-blocking" follow-up retained the same deadlock because the
// goroutine still wrote synchronously to the original fd. Both versions
// were architecturally wrong for a daemon that must never lose its own
// stderr — diagnosed 2026-04-07 on lab-node-2 and removed entirely.
//
// If a future board genuinely needs a userspace mirror (no working
// kernel console at all), implement it as a fully detached process or
// a lossy ring buffer that never shares an fd with the rest of the
// binary. Do not reintroduce a pipe that any caller of fmt.Fprintf
// can wedge on.

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
