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
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// threadChildEnv turns a re-executed test binary into a thread child: instead
// of running the tests it pins goroutines to OS threads of their own, makes a
// drop through kernelHardenOps and reports what every thread holds (#657).
const threadChildEnv = "GATEWAYD_PROCESS_TEST_THREAD_CHILD"

const (
	threadChildDrop   = "drop"
	threadChildRefuse = "refuse"
)

// pinnedThreads is how many goroutines the thread child locks to OS threads
// of their own before the drop, so the process holds threads the dropping
// goroutine never ran on.
const pinnedThreads = 4

// noCapabilities is a capability set with no bit raised, as
// /proc/<pid>/task/<tid>/status prints it.
const noCapabilities = "0000000000000000"

var threadChildRoles = map[string]func() int{
	threadChildDrop:   reportDrop,
	threadChildRefuse: reportRefusals,
}

func TestMain(m *testing.M) {
	if role, child := os.LookupEnv(threadChildEnv); child {
		os.Exit(runThreadChild(role))
	}
	os.Exit(m.Run())
}

// runThreadChild pins the threads, runs the role and returns its exit code.
func runThreadChild(role string) int {
	report, known := threadChildRoles[role]
	if !known {
		fmt.Fprintf(os.Stderr, "unknown thread child role %q\n", role)
		return 2
	}
	release := pinThreads(pinnedThreads)
	defer close(release)
	return report()
}

// pinThreads starts n goroutines that each lock themselves to an OS thread and
// park there until release is closed. It returns once all n hold their thread.
func pinThreads(n int) chan struct{} {
	release := make(chan struct{})
	pinned := make(chan struct{})
	for range n {
		go func() {
			runtime.LockOSThread()
			pinned <- struct{}{}
			<-release
		}()
	}
	for range n {
		<-pinned
	}
	return release
}

// reportDrop sets no_new_privs and clears every capability set through
// kernelHardenOps, then prints one line per thread: its tid, NoNewPrivs,
// CapPrm, CapEff and CapBnd. Clearing the sets needs no privilege, and run as
// root it is a real drop.
func reportDrop() int {
	ops := kernelHardenOps{}
	if err := ops.prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "no_new_privs:", err)
		return 1
	}
	if err := ops.capset(&[2]unix.CapUserData{}); err != nil {
		fmt.Fprintln(os.Stderr, "capset:", err)
		return 1
	}
	statuses, err := readTaskStatuses()
	if err != nil {
		fmt.Fprintln(os.Stderr, "task statuses:", err)
		return 1
	}
	for tid, status := range statuses {
		fields := parseStatus(status)
		fmt.Println(tid, fields["NoNewPrivs"], fields["CapPrm"], fields["CapEff"], fields["CapBnd"])
	}
	return 0
}

// reportRefusals asks for two changes the kernel refuses whoever asks, an
// invalid no_new_privs value and a permitted capability the process no longer
// holds, and prints each refusal.
func reportRefusals() int {
	ops := kernelHardenOps{}
	if err := ops.capset(&[2]unix.CapUserData{}); err != nil {
		fmt.Fprintln(os.Stderr, "capset:", err)
		return 1
	}
	raise := [2]unix.CapUserData{{Permitted: 1 << unix.CAP_CHOWN}}
	fmt.Println("prctl", ops.prctl(unix.PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0))
	fmt.Println("capset", ops.capset(&raise))
	return 0
}

// threadChildOutput runs the test binary again as a thread child in the given
// role and returns what it printed.
func threadChildOutput(t *testing.T, role string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0]) // #nosec G204 -- the test binary re-executes itself
	cmd.Env = append(os.Environ(), threadChildEnv+"="+role)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "thread child %s: %s", role, stderr.String())
	return string(out)
}

func TestKernelHardenOps_DropReachesEveryThread(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(threadChildOutput(t, threadChildDrop)), "\n")
	require.Greater(t, len(lines), pinnedThreads, "the child reports its pinned threads and the one that dropped")

	// The drop leaves the bounding set alone, so every thread keeps the one
	// the first reported thread holds.
	first := strings.Fields(lines[0])
	bounding := first[len(first)-1]
	for _, line := range lines {
		fields := strings.Fields(line)
		require.Len(t, fields, 5, line)
		assert.Equal(t, []string{"1", noCapabilities, noCapabilities, bounding}, fields[1:], "thread %s", fields[0])
	}
}

func TestKernelHardenOps_ReturnsTheKernelsRefusal(t *testing.T) {
	want := "prctl " + unix.EINVAL.Error() + "\ncapset " + unix.EPERM.Error() + "\n"
	assert.Equal(t, want, threadChildOutput(t, threadChildRefuse))
}

func TestCapValues_ListsEverySetBit(t *testing.T) {
	assert.Equal(t, []cap.Value{cap.CHOWN, cap.NET_ADMIN, 63}, capValues(1<<cap.CHOWN|1<<cap.NET_ADMIN|1<<63))
}

func TestCapValues_ListsNothingForAnEmptyMask(t *testing.T) {
	assert.Empty(t, capValues(0))
}
