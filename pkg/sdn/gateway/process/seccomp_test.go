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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// filterTable is a synthetic table with a second ABI, so the program's
// logic is tested the same way on every architecture.
var filterTable = seccompTable{
	arch:   0xc000003e,
	abiBit: 0x40000000,
	denied: []uint32{165, 101},
	exec:   []uint32{59, 322},
	clone:  56,
	clone3: 435,
}

// evaluate runs program over one syscall and returns its verdict. The x/net
// VM loads words big-endian, as a packet filter does, while the kernel loads
// seccomp_data in host order; writing each word big-endian makes the VM read
// the value the kernel would.
func evaluate(t *testing.T, program []bpf.Instruction, arch, nr, arg0 uint32) int {
	t.Helper()
	vm, err := bpf.NewVM(program)
	require.NoError(t, err)
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[seccompDataNr:], nr)
	binary.BigEndian.PutUint32(data[seccompDataArch:], arch)
	binary.BigEndian.PutUint32(data[seccompDataArg0:], arg0)
	verdict, err := vm.Run(data)
	require.NoError(t, err)
	return verdict
}

func TestSeccompProgram_DeniesTheTableToEveryClass(t *testing.T) {
	for _, class := range []Class{ClassKernel, ClassParser} {
		program := seccompProgram(filterTable, class)
		for _, nr := range filterTable.denied {
			assert.Equalf(t, int(seccompDeny), evaluate(t, program, filterTable.arch, nr, 0),
				"%s class, syscall %d", class, nr)
		}
	}
}

func TestSeccompProgram_AllowsWhatTheTableDoesNotName(t *testing.T) {
	program := seccompProgram(filterTable, ClassParser)

	assert.Equal(t, int(seccompAllow), evaluate(t, program, filterTable.arch, 0, 0), "read")
	assert.Equal(t, int(seccompAllow), evaluate(t, program, filterTable.arch, 41, 0), "socket")
}

func TestSeccompProgram_OnlyTheKernelClassMayExec(t *testing.T) {
	for _, nr := range filterTable.exec {
		assert.Equal(t, int(seccompDeny), evaluate(t, seccompProgram(filterTable, ClassParser), filterTable.arch, nr, 0),
			"a parser never execs")
		assert.Equal(t, int(seccompAllow), evaluate(t, seccompProgram(filterTable, ClassKernel), filterTable.arch, nr, 0),
			"the datapath's nat64 service runs jool")
	}
}

func TestSeccompProgram_KillsAForeignArchitecture(t *testing.T) {
	program := seccompProgram(filterTable, ClassKernel)

	// i386's read on an x86-64 kernel: a number the table does not describe.
	assert.Equal(t, int(seccompKill), evaluate(t, program, unix.AUDIT_ARCH_I386, 3, 0))
}

func TestSeccompProgram_DeniesTheSecondABI(t *testing.T) {
	program := seccompProgram(filterTable, ClassKernel)

	assert.Equal(t, int(seccompDeny), evaluate(t, program, filterTable.arch, filterTable.abiBit, 0),
		"x32 read is not the native read the table allows")
}

func TestSeccompProgram_ClonePassesUnlessItAsksForANamespace(t *testing.T) {
	program := seccompProgram(filterTable, ClassParser)
	// The flags the Go runtime starts a thread with.
	thread := uint32(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND |
		unix.CLONE_SYSVSEM | unix.CLONE_THREAD)

	assert.Equal(t, int(seccompAllow), evaluate(t, program, filterTable.arch, filterTable.clone, thread))
	for _, flag := range []uint32{
		unix.CLONE_NEWNS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWUTS, unix.CLONE_NEWIPC,
		unix.CLONE_NEWUSER, unix.CLONE_NEWPID, unix.CLONE_NEWNET,
	} {
		assert.Equalf(t, int(seccompDeny), evaluate(t, program, filterTable.arch, filterTable.clone, thread|flag),
			"clone flag %#x", flag)
	}
}

func TestSeccompProgram_Clone3FallsBackToClone(t *testing.T) {
	// clone3's flags sit behind a pointer the filter cannot follow, so it
	// is refused as unimplemented and the caller retries with clone.
	program := seccompProgram(filterTable, ClassKernel)

	assert.Equal(t, int(seccompNoSys), evaluate(t, program, filterTable.arch, filterTable.clone3, 0))
}

func TestSeccompProgram_LeavesTheTableUnchanged(t *testing.T) {
	// A denied list with spare capacity: appending a parser's exec entries
	// in place would write them into the shared table's backing array.
	backing := make([]uint32, 2, 4)
	copy(backing, filterTable.denied)
	table := filterTable
	table.denied = backing

	seccompProgram(table, ClassParser)

	assert.Equal(t, []uint32{0, 0}, backing[2:4], "the exec entries are not appended into the shared table")
}

func TestSeccompFilter_AssemblesTheProgram(t *testing.T) {
	program := seccompProgram(filterTable, ClassParser)

	filter, err := seccompFilter(filterTable, ClassParser)

	require.NoError(t, err)
	require.Len(t, filter, len(program))
	raw, err := program[0].Assemble()
	require.NoError(t, err)
	assert.Equal(t, unix.SockFilter{Code: raw.Op, Jt: raw.Jt, Jf: raw.Jf, K: raw.K}, filter[0])
}

func TestAssembleSeccomp_RejectsAnInvalidInstruction(t *testing.T) {
	_, err := assembleSeccomp([]bpf.Instruction{bpf.LoadAbsolute{Off: 0, Size: 3}})

	require.Error(t, err)
}

func TestKernelHardenOpsSeccomp_RefusesAFilterTheKernelWouldReject(t *testing.T) {
	// Both are refused before the syscall, so the test binary is never
	// filtered.
	assert.ErrorIs(t, kernelHardenOps{}.seccomp(nil), unix.EINVAL)
	assert.ErrorIs(t, kernelHardenOps{}.seccomp(make([]unix.SockFilter, unix.BPF_MAXINSNS+1)), unix.EINVAL)
}
