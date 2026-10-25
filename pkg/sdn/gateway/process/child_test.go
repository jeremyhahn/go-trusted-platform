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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeStages serves canned thread statuses and a syscall table.
type fakeStages struct {
	harden *recordingHardenOps

	statuses    map[string]string
	statusErr   error
	statusReads int
	syscallsErr error
}

// testSeccompTable stands in for the native table, so the stage tests do
// not depend on the architecture they run on.
var testSeccompTable = seccompTable{arch: 1, denied: []uint32{2}, exec: []uint32{3}, clone: 4, clone3: 5, socket: 6, socketpair: 7}

func newFakeStages() *fakeStages {
	return &fakeStages{harden: newRecordingHardenOps()}
}

func (f *fakeStages) ops() childOps {
	return childOps{
		harden: f.harden,
		taskStatuses: func() (map[string]string, error) {
			f.statusReads++
			return f.statuses, f.statusErr
		},
		syscalls: func() (seccompTable, error) {
			return testSeccompTable, f.syscallsErr
		},
	}
}

// procStatus renders a thread status document the way procfs does: tab
// separated, the group list with a trailing space.
func procStatus(noNewPrivs, caps, uid, gid string) string {
	return "Name:\tgatewayd\n" +
		"Uid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\n" +
		"Gid:\t" + gid + "\t" + gid + "\t" + gid + "\t" + gid + "\n" +
		"Groups:\t" + gid + " \n" +
		"NoNewPrivs:\t" + noNewPrivs + "\n" +
		"Seccomp:\t2\n" +
		"CapInh:\t" + caps + "\n" +
		"CapPrm:\t" + caps + "\n" +
		"CapEff:\t" + caps + "\n" +
		"CapBnd:\t" + caps + "\n" +
		"CapAmb:\t" + caps + "\n"
}

const routingCaps = "0000000000000400" // CAP_NET_BIND_SERVICE

func routing(t *testing.T) Definition {
	t.Helper()
	def, err := DefinitionByName("routing")
	require.NoError(t, err)
	return def
}

func TestEnterHardened_DropsThenConfinesThenVerifiesEveryThread(t *testing.T) {
	child := newFakeStages()
	child.statuses = map[string]string{
		"100": procStatus("1", routingCaps, "1000", "1000"),
		"101": procStatus("1", routingCaps, "1000", "1000"),
	}

	require.NoError(t, enterHardened(routing(t), 1000, 1000, child.ops()))

	assert.Equal(t, []string{
		"no_new_privs", "capbset_drop", "setgroups", "keepcaps=1",
		"setresgid", "setresuid", "capset", "cap_ambient_raise", "keepcaps=0",
		"pdeathsig", "seccomp",
	}, child.harden.calls, "the whole drop, then the filter; nothing is re-executed")
	want, err := seccompFilter(testSeccompTable, routing(t))
	require.NoError(t, err)
	assert.Equal(t, want, child.harden.filter, "the routing process's filter is the one installed")
	assert.Equal(t, 1, child.statusReads, "every thread is read back after the filter is on")
}

func TestEnterHardened_StopsWhenTheDropFails(t *testing.T) {
	child := newFakeStages()
	child.harden.failAt, child.harden.failWith = "setresuid", unix.EPERM

	err := enterHardened(routing(t), 1000, 1000, child.ops())

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "drop uid", hardening.Step)
	assert.NotContains(t, child.harden.calls, "seccomp")
	assert.Zero(t, child.statusReads)
}

func TestEnterHardened_RefusesWithoutASyscallTable(t *testing.T) {
	child := newFakeStages()
	child.syscallsErr = &ErrSeccompUnsupportedArch{Arch: "riscv64"}
	child.statuses = map[string]string{"100": procStatus("1", routingCaps, "1000", "1000")}

	err := enterHardened(routing(t), 1000, 1000, child.ops())

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "build the seccomp filter", hardening.Step)
	var unsupported *ErrSeccompUnsupportedArch
	require.ErrorAs(t, err, &unsupported)
	assert.NotContains(t, child.harden.calls, "seccomp", "a child with no filter installs none")
	assert.Zero(t, child.statusReads)
}

func TestEnterHardened_StopsWhenTheFilterIsRefused(t *testing.T) {
	child := newFakeStages()
	child.harden.failAt, child.harden.failWith = "seccomp", unix.EACCES
	child.statuses = map[string]string{"100": procStatus("1", routingCaps, "1000", "1000")}

	err := enterHardened(routing(t), 1000, 1000, child.ops())

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "install the seccomp filter", hardening.Step)
	require.ErrorIs(t, err, unix.EACCES)
	assert.Zero(t, child.statusReads, "an unconfined process is not verified, it is refused")
}

func TestEnterHardened_AcceptsARootKernelClass(t *testing.T) {
	def, err := DefinitionByName("datapath")
	require.NoError(t, err)
	child := newFakeStages()
	// CAP_NET_ADMIN and CAP_NET_RAW, as root: the uid is not the class's to
	// change, so a root uid is not a finding.
	child.statuses = map[string]string{"7": procStatus("1", "0000000000003000", "0", "0")}

	require.NoError(t, enterHardened(def, 1000, 1000, child.ops()))
}

func TestEnterHardened_RefusesWhenTheSupervisorDiedDuringTheDrop(t *testing.T) {
	child := newFakeStages()
	child.harden.ppid, child.harden.ppidAfter = 4242, 1
	child.statuses = map[string]string{"100": procStatus("1", routingCaps, "1000", "1000")}

	err := enterHardened(routing(t), 1000, 1000, child.ops())

	var exited *ErrSupervisorExited
	require.ErrorAs(t, err, &exited)
	assert.Equal(t, 4242, exited.Parent)
	assert.NotContains(t, child.harden.calls, "seccomp", "an orphan goes no further")
}

func TestEnterHardened_RefusesWithoutThreadCredentials(t *testing.T) {
	for name, child := range map[string]*fakeStages{
		"read error": func() *fakeStages {
			child := newFakeStages()
			child.statusErr = unix.EACCES
			return child
		}(),
		"no threads": newFakeStages(),
	} {
		t.Run(name, func(t *testing.T) {
			err := enterHardened(routing(t), 1000, 1000, child.ops())

			var hardening *ErrHardening
			require.ErrorAs(t, err, &hardening)
			assert.Equal(t, "read the thread credentials", hardening.Step)
		})
	}
}

func TestEnterHardened_RejectsAThreadOutsideTheClass(t *testing.T) {
	cases := map[string]struct {
		status string
		field  string
	}{
		"no_new_privs unset":  {procStatus("0", routingCaps, "1000", "1000"), "NoNewPrivs"},
		"extra capability":    {procStatus("1", "0000000000001400", "1000", "1000"), "CapPrm"},
		"still root":          {procStatus("1", routingCaps, "0", "1000"), "Uid"},
		"root group":          {procStatus("1", routingCaps, "1000", "0"), "Gid"},
		"no capability field": {"Name:\tgatewayd\nNoNewPrivs:\t1\nSeccomp:\t2\n", "CapPrm"},
		"no seccomp filter": {
			strings.Replace(procStatus("1", routingCaps, "1000", "1000"), "Seccomp:\t2", "Seccomp:\t0", 1),
			"Seccomp",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			child := newFakeStages()
			// The good thread sorts first, so the finding is the second one.
			child.statuses = map[string]string{
				"100": procStatus("1", routingCaps, "1000", "1000"),
				"200": tc.status,
			}

			err := enterHardened(routing(t), 1000, 1000, child.ops())

			var notHeld *ErrPrivilegeNotHeld
			require.ErrorAs(t, err, &notHeld)
			assert.Equal(t, "200", notHeld.Task)
			assert.Equal(t, tc.field, notHeld.Field)
		})
	}
}

func TestCheckTaskStatus_RejectsExtraSupplementaryGroups(t *testing.T) {
	status := procStatus("1", routingCaps, "1000", "1000") + "Groups:\t1000 10 \n"

	err := checkTaskStatus(routing(t), 1000, 1000, "1", status)

	var notHeld *ErrPrivilegeNotHeld
	require.ErrorAs(t, err, &notHeld)
	assert.Equal(t, "Groups", notHeld.Field)
	assert.Equal(t, "1000 10", notHeld.Got)
}

func TestParseStatus_NormalisesWhitespaceAndSkipsMalformedLines(t *testing.T) {
	fields := parseStatus("Uid:\t0\t0\t0\t0\nnot a field\nGroups:\t \n")

	assert.Equal(t, "0 0 0 0", fields["Uid"])
	assert.Equal(t, "", fields["Groups"])
	assert.Len(t, fields, 2)
}

func TestParseStatus_EmptyDocumentHasNoFields(t *testing.T) {
	assert.Empty(t, parseStatus(""))
}

func TestCapabilityMask(t *testing.T) {
	assert.Equal(t, uint64(0x400), capabilityMask([]uintptr{unix.CAP_NET_BIND_SERVICE}))
	assert.Equal(t, uint64(0x3000), capabilityMask([]uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}))
	// A capability above 31 lands in the upper word, which capset sends as
	// the second CapUserData.
	assert.Equal(t, uint64(1)<<unix.CAP_BPF, capabilityMask([]uintptr{unix.CAP_BPF}))
}

func TestCapabilityMask_NoCapabilitiesIsTheEmptySet(t *testing.T) {
	assert.Zero(t, capabilityMask(nil))
}

func TestTaskStatusesIn_ReadsEveryThreadAndSkipsOnesThatExited(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "100"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "100", "status"), []byte("NoNewPrivs:\t1\n"), 0o600))
	// A thread directory whose status is gone exited mid-listing.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "101"), 0o700))

	statuses, err := taskStatusesIn(dir)

	require.NoError(t, err)
	assert.Equal(t, map[string]string{"100": "NoNewPrivs:\t1\n"}, statuses)
}

func TestTaskStatusesIn_MissingDirectoryIsAnError(t *testing.T) {
	_, err := taskStatusesIn(filepath.Join(t.TempDir(), "absent"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadTaskStatuses_ReadsThisProcess(t *testing.T) {
	statuses, err := readTaskStatuses()

	require.NoError(t, err)
	require.NotEmpty(t, statuses)
	for _, status := range statuses {
		assert.Contains(t, parseStatus(status), "CapEff")
	}
}
