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

//go:build amd64 || arm64

package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNativeSeccompTable_DeniesTheKernelSurfaceAGatewayNeverUses(t *testing.T) {
	table, err := nativeSeccompTable()
	require.NoError(t, err)

	for name, nr := range map[string]uint32{
		"mount": unix.SYS_MOUNT, "ptrace": unix.SYS_PTRACE, "bpf": unix.SYS_BPF,
		"unshare": unix.SYS_UNSHARE, "setns": unix.SYS_SETNS, "init_module": unix.SYS_INIT_MODULE,
		"io_uring_setup": unix.SYS_IO_URING_SETUP, "keyctl": unix.SYS_KEYCTL,
	} {
		assert.Containsf(t, table.denied, nr, "%s is denied to every class", name)
	}
	assert.ElementsMatch(t, []uint32{unix.SYS_EXECVE, unix.SYS_EXECVEAT}, table.exec)
}

func TestNativeSeccompTable_LeavesTheGatewaysOwnCallsAlone(t *testing.T) {
	table, err := nativeSeccompTable()
	require.NoError(t, err)

	for name, nr := range map[string]uint32{
		"read": unix.SYS_READ, "socket": unix.SYS_SOCKET, "setsockopt": unix.SYS_SETSOCKOPT,
		"sendmsg": unix.SYS_SENDMSG, "futex": unix.SYS_FUTEX, "clone": unix.SYS_CLONE,
		"execve": unix.SYS_EXECVE,
	} {
		assert.NotContainsf(t, table.denied, nr, "%s is not in the shared denied list", name)
	}
	assert.Equal(t, uint32(unix.SYS_CLONE), table.clone)
	assert.Equal(t, uint32(unix.SYS_CLONE3), table.clone3)
}
