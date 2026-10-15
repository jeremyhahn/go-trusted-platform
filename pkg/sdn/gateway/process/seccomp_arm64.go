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

import "golang.org/x/sys/unix"

// nativeSeccompTable is the arm64 table. arm64 has one ABI, so there is no
// second-ABI bit to deny.
func nativeSeccompTable() (seccompTable, error) {
	return seccompTable{
		arch:   unix.AUDIT_ARCH_AARCH64,
		denied: deniedSyscalls,
		exec:   execSyscalls,
		clone:  unix.SYS_CLONE,
		clone3: unix.SYS_CLONE3,
	}, nil
}
