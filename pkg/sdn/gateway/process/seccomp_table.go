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

import "golang.org/x/sys/unix"

// deniedSyscalls are the calls no gateway service makes, on every
// architecture with a table. Each group is kernel surface a compromised
// service could otherwise reach with the capabilities it legitimately holds,
// or with none at all.
var deniedSyscalls = []uint32{
	// Loading code into, or replacing, the kernel.
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_QUOTACTL, unix.SYS_SYSLOG,
	// Changing what the filesystem tree is.
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	// Entering or creating namespaces; clone's namespace flags are checked
	// separately.
	unix.SYS_UNSHARE, unix.SYS_SETNS,
	// Reading or writing another process.
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_KCMP, unix.SYS_PIDFD_GETFD,
	// Kernel interfaces with a long exploit history and no gateway use.
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_FANOTIFY_INIT,
	// The host's clock and identity.
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME,
	unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME,
}

// execSyscalls replace the process image.
var execSyscalls = []uint32{unix.SYS_EXECVE, unix.SYS_EXECVEAT}
