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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// childOps is what EnterHardened needs from the operating system, so the
// drop is a unit test rather than irreversible syscalls on the test binary.
type childOps struct {
	harden hardenOps
	// taskStatuses returns /proc/self/task/<tid>/status for every thread.
	taskStatuses func() (map[string]string, error)
	// syscalls returns this architecture's seccomp syscall table.
	syscalls func() (seccompTable, error)
}

// EnterHardened drops a child to its class and returns only in a process
// whose every thread holds exactly the class's credentials.
//
// The Go runtime has started several threads before main runs, and every
// credential the drop changes is a property of one thread (#657). harden
// therefore makes each change on every thread at once — the uid, gid and
// groups through the standard library, the prctl and capset calls through
// libcap's psx mechanism — then the class's seccomp filter is installed on
// every thread, and every thread is read back and checked against the
// class. A failure at any step is fatal to the child.
func EnterHardened(def Definition, uid, gid uint32) error {
	return enterHardened(def, uid, gid, childOps{
		harden:       kernelHardenOps{},
		taskStatuses: readTaskStatuses,
		syscalls:     nativeSeccompTable,
	})
}

func enterHardened(def Definition, uid, gid uint32, ops childOps) error {
	if err := harden(def, uid, gid, ops.harden); err != nil {
		return err
	}
	if err := confineSyscalls(def, ops); err != nil {
		return err
	}
	return verifyThreads(def, uid, gid, ops)
}

// verifyThreads reads every thread back and refuses unless each one holds
// exactly the class's credentials and the seccomp filter. It is what proves
// the drop reached every thread, rather than trusting that it did.
func verifyThreads(def Definition, uid, gid uint32, ops childOps) error {
	statuses, err := ops.taskStatuses()
	if err != nil {
		return &ErrHardening{Step: "read the thread credentials", Cause: err}
	}
	if len(statuses) == 0 {
		return &ErrHardening{Step: "read the thread credentials", Cause: os.ErrNotExist}
	}
	tasks := make([]string, 0, len(statuses))
	for task := range statuses {
		tasks = append(tasks, task)
	}
	slices.Sort(tasks)
	for _, task := range tasks {
		if err := checkTaskStatus(def, uid, gid, task, statuses[task]); err != nil {
			return &ErrHardening{Step: "verify the hardened credentials", Cause: err}
		}
	}
	return nil
}

// confineSyscalls installs the process's seccomp filter on every thread. It
// proves nothing by itself: the credential check that follows reads each
// thread's Seccomp field, so a thread the kernel left unfiltered fails the
// child.
func confineSyscalls(def Definition, ops childOps) error {
	table, err := ops.syscalls()
	if err != nil {
		return &ErrHardening{Step: "build the seccomp filter", Cause: err}
	}
	filter, err := seccompFilter(table, def)
	if err != nil {
		return &ErrHardening{Step: "build the seccomp filter", Cause: err}
	}
	if err := ops.harden.seccomp(filter); err != nil {
		return &ErrHardening{Step: "install the seccomp filter", Cause: err}
	}
	return nil
}

// checkTaskStatus compares one thread's /proc status with the class. The
// capability sets that decide what a thread can do — permitted, effective
// and bounding — must equal the class mask exactly. Ambient is not checked:
// it only carries capabilities across an exec, and the permitted and
// effective sets already show what the exec produced from it. Seccomp must
// read 2, filter mode: the thread carries the filter confineSyscalls
// installed.
func checkTaskStatus(def Definition, uid, gid uint32, task, status string) error {
	fields := parseStatus(status)
	mask := fmt.Sprintf("%016x", capabilityMask(def.Capabilities))
	want := map[string]string{
		"NoNewPrivs": "1",
		"Seccomp":    "2",
		"CapPrm":     mask,
		"CapEff":     mask,
		"CapBnd":     mask,
	}
	if def.Unprivileged {
		u, g := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
		want["Uid"] = strings.Join([]string{u, u, u, u}, " ")
		want["Gid"] = strings.Join([]string{g, g, g, g}, " ")
		want["Groups"] = g
	}
	for _, field := range []string{"NoNewPrivs", "Seccomp", "CapPrm", "CapEff", "CapBnd", "Uid", "Gid", "Groups"} {
		expected, checked := want[field]
		if !checked {
			continue
		}
		if got := fields[field]; got != expected {
			return &ErrPrivilegeNotHeld{Task: task, Field: field, Want: expected, Got: got}
		}
	}
	return nil
}

// parseStatus reads a /proc status document into field -> value, with the
// value's whitespace-separated words joined by single spaces.
func parseStatus(status string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(status, "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields[name] = strings.Join(strings.Fields(value), " ")
	}
	return fields
}

// capabilityMask is the kernel's 64-bit capability set holding capabilities.
func capabilityMask(capabilities []uintptr) uint64 {
	var mask uint64
	for _, capability := range capabilities {
		mask |= 1 << capability
	}
	return mask
}

// readTaskStatuses reads the status document of every thread of this
// process. The documents are world-readable, so this works after the drop.
func readTaskStatuses() (map[string]string, error) {
	return taskStatusesIn("/proc/self/task")
}

// taskStatusesIn reads <taskDir>/<tid>/status for every thread directory.
func taskStatusesIn(taskDir string) (map[string]string, error) {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}
	statuses := make(map[string]string, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(taskDir, entry.Name(), "status")) // #nosec G304 -- a procfs thread path
		if err != nil {
			// A thread that exits between the listing and the read has no
			// credentials left to check.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		statuses[entry.Name()] = string(data)
	}
	return statuses, nil
}
