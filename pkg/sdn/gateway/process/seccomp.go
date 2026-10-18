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

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Offsets into struct seccomp_data, the record a seccomp filter reads.
const (
	seccompDataNr   = 0
	seccompDataArch = 4
	// seccompDataArg0 is the low 32 bits of the first argument. Every
	// architecture with a syscall table is little-endian, so the low half
	// comes first.
	seccompDataArg0 = 16
)

// The filter's verdicts. A denied call fails with EPERM rather than killing
// the child, so a library probing for a feature degrades instead of taking
// the service down; only a foreign architecture, which no syscall number in
// the table describes, kills the process.
const (
	seccompAllow uint32 = unix.SECCOMP_RET_ALLOW
	seccompKill  uint32 = unix.SECCOMP_RET_KILL_PROCESS
	seccompDeny  uint32 = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	seccompNoSys uint32 = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	// seccompNoFamily answers a socket in an address family the process
	// does not use, as a kernel built without that family would.
	seccompNoFamily uint32 = unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)
)

// namespaceCloneFlags are the clone flags that create a namespace. A gateway
// service never needs one, and a new user namespace is the usual first step
// from an unprivileged process to kernel attack surface it could not
// otherwise reach.
const namespaceCloneFlags uint32 = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS |
	unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// seccompTable is one architecture's syscall numbers for the filter.
type seccompTable struct {
	// arch is the AUDIT_ARCH value seccomp_data carries for this ABI.
	arch uint32
	// abiBit, when non-zero, marks a second ABI that shares arch (x32 on
	// amd64). Every number carrying it is denied: the table describes the
	// native ABI only.
	abiBit uint32
	// denied are refused to every class.
	denied []uint32
	// exec are execve and execveat, refused to every class but the kernel
	// class, whose nat64 service runs jool.
	exec []uint32
	// clone and clone3 are checked separately: clone's flags are an
	// argument the filter can read, clone3's are behind a pointer.
	clone, clone3 uint32
	// socket and socketpair are checked against the process's address
	// families; both take the family as their first argument.
	socket, socketpair uint32
}

// seccompProgram is the process's filter over table. In order: a foreign
// architecture is killed, the second ABI is denied, every denied number
// fails with EPERM, a socket outside the process's address families fails
// with EAFNOSUPPORT, clone3 fails with ENOSYS so the runtime and libc fall
// back to clone, and clone is denied only when it asks for a namespace.
// Everything else is allowed: the filter removes the kernel interfaces a
// gateway service never uses rather than listing the ones it does, so a
// library update cannot break a service by making a new, harmless call.
// Address families are the exception, an allow list per process, because
// the families are few and each one a process does not open is kernel
// surface (AF_PACKET, AF_VSOCK, the protocol families) it never reaches.
func seccompProgram(table seccompTable, def Definition) []bpf.Instruction {
	denied := table.denied
	if def.Class != ClassKernel {
		denied = append(slices.Clip(denied), table.exec...)
	}
	program := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompDataArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: table.arch, SkipTrue: 1},
		bpf.RetConstant{Val: seccompKill},
		bpf.LoadAbsolute{Off: seccompDataNr, Size: 4},
	}
	if table.abiBit != 0 {
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: table.abiBit, SkipFalse: 1},
			bpf.RetConstant{Val: seccompDeny},
		)
	}
	for _, nr := range denied {
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 1},
			bpf.RetConstant{Val: seccompDeny},
		)
	}
	program = append(program, familyCheck(table, def.AddressFamilies)...)
	return append(program,
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: table.clone3, SkipFalse: 1},
		bpf.RetConstant{Val: seccompNoSys},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: table.clone, SkipFalse: 3},
		bpf.LoadAbsolute{Off: seccompDataArg0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: namespaceCloneFlags, SkipFalse: 1},
		bpf.RetConstant{Val: seccompDeny},
		bpf.RetConstant{Val: seccompAllow},
	)
}

// familyCheck is the address-family allow list. It runs with the syscall
// number in the accumulator and leaves it there for every other call; for
// socket and socketpair it loads the family argument and returns, allowing
// a listed family and failing any other with EAFNOSUPPORT. An empty list
// therefore refuses every socket.
func familyCheck(table seccompTable, families []uint32) []bpf.Instruction {
	count := len(families)
	check := []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: table.socket, SkipTrue: 1},
		// Not socketpair either: skip the load, the comparisons and both
		// returns.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: table.socketpair, SkipFalse: uint8(count + 3)},
		bpf.LoadAbsolute{Off: seccompDataArg0, Size: 4},
	}
	for i, family := range families {
		// A match skips the remaining comparisons and the refusal.
		check = append(check, bpf.JumpIf{Cond: bpf.JumpEqual, Val: family, SkipTrue: uint8(count - i)})
	}
	return append(check,
		bpf.RetConstant{Val: seccompNoFamily},
		bpf.RetConstant{Val: seccompAllow},
	)
}

// seccompFilter assembles the process's filter over table into the form
// seccomp(2) loads.
func seccompFilter(table seccompTable, def Definition) ([]unix.SockFilter, error) {
	return assembleSeccomp(seccompProgram(table, def))
}

// assembleSeccomp converts a classic BPF program to the kernel's
// sock_filter layout.
func assembleSeccomp(program []bpf.Instruction) ([]unix.SockFilter, error) {
	raw, err := bpf.Assemble(program)
	if err != nil {
		return nil, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, instruction := range raw {
		filter[i] = unix.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	return filter, nil
}
