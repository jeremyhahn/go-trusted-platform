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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// hardenedParentEnv marks the re-executed image of a hardened child and
// carries the supervisor's pid across the exec, so the second stage can tell
// whether the supervisor died while the parent-death signal was disarmed.
// The marker grants nothing: the second stage verifies its credentials
// against the class before it trusts them.
const hardenedParentEnv = "GATEWAYD_HARDENED_PARENT"

// childOps is what EnterHardened needs from the operating system, so both
// stages are unit tests rather than irreversible syscalls on the test binary.
type childOps struct {
	harden hardenOps
	// executable resolves this binary before the drop, while root can
	// still read every path to it.
	executable func() (string, error)
	// exec replaces the process image from the calling thread.
	exec func(path string, argv, env []string) error
	// args and environ are this process's own.
	args    []string
	environ []string
	// taskStatuses returns /proc/self/task/<tid>/status for every thread.
	taskStatuses func() (map[string]string, error)
}

// EnterHardened drops a child to its class and returns only in a process
// whose every thread holds exactly the class's credentials.
//
// prctl and capset change the calling thread only, while the Go runtime has
// started several threads before main runs (#657). So the first stage locks
// its goroutine to one thread, hardens that thread, and re-executes the
// binary from it: execve keeps the calling thread's credentials and discards
// every other thread, and every thread the new runtime starts is cloned from
// the hardened one. The second stage, recognised by hardenedParentEnv,
// verifies every thread against the class and re-arms the parent-death
// signal. A failure in either stage is fatal to the child.
func EnterHardened(def Definition, uid, gid uint32) error {
	// The lock is never released: on success the image is replaced, and on
	// failure the child exits, so no other goroutine may run on a
	// half-hardened thread in between.
	runtime.LockOSThread()
	return enterHardened(def, uid, gid, childOps{
		harden:       kernelHardenOps{},
		executable:   os.Executable,
		exec:         syscall.Exec,
		args:         os.Args,
		environ:      os.Environ(),
		taskStatuses: readTaskStatuses,
	})
}

func enterHardened(def Definition, uid, gid uint32, ops childOps) error {
	if marker, ok := lookupEnv(ops.environ, hardenedParentEnv); ok {
		return verifyHardened(def, uid, gid, marker, ops)
	}
	binary, err := ops.executable()
	if err != nil {
		return &ErrHardening{Step: "resolve the executable to re-execute", Cause: err}
	}
	parent := ops.harden.getppid()
	if err := harden(def, uid, gid, ops.harden); err != nil {
		return err
	}
	// The marker is absent here, or this would be the second stage.
	env := append(slices.Clip(ops.environ), hardenedParentEnv+"="+strconv.Itoa(parent))
	err = ops.exec(binary, ops.args, env)
	return &ErrHardening{Step: "re-execute from the hardened thread", Cause: err}
}

// verifyHardened is the second stage: every thread must already hold the
// class's credentials, then the parent-death signal is re-armed against the
// supervisor the first stage saw.
func verifyHardened(def Definition, uid, gid uint32, marker string, ops childOps) error {
	parent, err := strconv.Atoi(marker)
	if err != nil {
		return &ErrHardening{Step: "read the hardened-stage marker", Cause: err}
	}
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
	return rearmParentDeath(parent, ops.harden)
}

// checkTaskStatus compares one thread's /proc status with the class. The
// capability sets that decide what a thread can do — permitted, effective
// and bounding — must equal the class mask exactly. Ambient is not checked:
// it only carries capabilities across an exec, and the permitted and
// effective sets already show what the exec produced from it.
func checkTaskStatus(def Definition, uid, gid uint32, task, status string) error {
	fields := parseStatus(status)
	mask := fmt.Sprintf("%016x", capabilityMask(def.Capabilities))
	want := map[string]string{
		"NoNewPrivs": "1",
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
	for _, field := range []string{"NoNewPrivs", "CapPrm", "CapEff", "CapBnd", "Uid", "Gid", "Groups"} {
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

func lookupEnv(environ []string, key string) (string, bool) {
	for _, entry := range environ {
		if value, found := strings.CutPrefix(entry, key+"="); found {
			return value, true
		}
	}
	return "", false
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
