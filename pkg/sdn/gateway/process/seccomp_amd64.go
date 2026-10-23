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

package process

import (
	"slices"

	"golang.org/x/sys/unix"
)

// x32SyscallBit marks an x32 syscall number on x86-64. x32 shares
// AUDIT_ARCH_X86_64 with the native ABI, so the architecture check alone
// does not shut it out.
const x32SyscallBit = 0x40000000

// nativeSeccompTable is the x86-64 table: the shared list plus the
// x86-only calls that reach I/O ports, segment descriptors or a.out
// loading.
func nativeSeccompTable() (seccompTable, error) {
	return seccompTable{
		arch:   unix.AUDIT_ARCH_X86_64,
		abiBit: x32SyscallBit,
		denied: slices.Concat(deniedSyscalls, []uint32{
			unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT, unix.SYS_USELIB,
		}),
		exec:       execSyscalls,
		clone:      unix.SYS_CLONE,
		clone3:     unix.SYS_CLONE3,
		socket:     unix.SYS_SOCKET,
		socketpair: unix.SYS_SOCKETPAIR,
	}, nil
}
