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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// errImageReplaced stands in for an exec that succeeded: the real one never
// returns, so the fake returns this and the test reads what it was given.
var errImageReplaced = errors.New("image replaced")

// fakeStages records the exec and serves canned thread statuses.
type fakeStages struct {
	harden *recordingHardenOps

	execPath string
	execArgv []string
	execEnv  []string
	execs    int

	statuses      map[string]string
	statusErr     error
	statusReads   int
	executable    string
	execErr       error
	executableErr error
}

func newFakeStages() *fakeStages {
	return &fakeStages{
		harden:     newRecordingHardenOps(),
		executable: "/usr/sbin/gatewayd",
		execErr:    errImageReplaced,
	}
}

func (f *fakeStages) ops(environ []string) childOps {
	return childOps{
		harden: f.harden,
		executable: func() (string, error) {
			return f.executable, f.executableErr
		},
		exec: func(path string, argv, env []string) error {
			f.execs++
			f.execPath, f.execArgv, f.execEnv = path, argv, env
			return f.execErr
		},
		args:    []string{"gatewayd", "service", "run", "routing"},
		environ: environ,
		taskStatuses: func() (map[string]string, error) {
			f.statusReads++
			return f.statuses, f.statusErr
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

func TestEnterHardened_FirstStageHardensTheThreadThenReexecutesWithTheMarker(t *testing.T) {
	child := newFakeStages()

	err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"PATH=/usr/bin"}))

	// The fake exec "returns", which the real one never does on success.
	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.ErrorIs(t, err, errImageReplaced)
	assert.Equal(t, 1, child.execs)
	assert.Equal(t, "/usr/sbin/gatewayd", child.execPath)
	assert.Equal(t, []string{"gatewayd", "service", "run", "routing"}, child.execArgv)
	assert.Equal(t, []string{"PATH=/usr/bin", "GATEWAYD_HARDENED_PARENT=4242"}, child.execEnv)
	// The whole drop ran on this thread before the exec.
	assert.Equal(t, 1000, child.harden.uid)
	assert.Equal(t, 1000, child.harden.gid)
	assert.Contains(t, child.harden.calls, "pdeathsig")
	assert.Zero(t, child.statusReads, "the first stage verifies nothing; the exec has not happened")
}

func TestEnterHardened_FirstStageRefusesWithoutTheExecutable(t *testing.T) {
	child := newFakeStages()
	child.executableErr = os.ErrNotExist

	err := enterHardened(routing(t), 1000, 1000, child.ops(nil))

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "resolve the executable to re-execute", hardening.Step)
	assert.Empty(t, child.harden.calls, "nothing is dropped when the re-exec cannot follow")
	assert.Zero(t, child.execs)
}

func TestEnterHardened_FirstStageStopsWhenTheDropFails(t *testing.T) {
	child := newFakeStages()
	child.harden.failAt = "setresuid"
	child.harden.failWith = unix.EPERM

	err := enterHardened(routing(t), 1000, 1000, child.ops(nil))

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "drop uid", hardening.Step)
	assert.Zero(t, child.execs, "a half-hardened thread is never re-executed")
}

func TestEnterHardened_FirstStageReportsAFailedExec(t *testing.T) {
	child := newFakeStages()
	child.execErr = unix.EACCES

	err := enterHardened(routing(t), 1000, 1000, child.ops(nil))

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "re-execute from the hardened thread", hardening.Step)
	assert.ErrorIs(t, err, unix.EACCES)
}

func TestEnterHardened_SecondStageVerifiesEveryThreadAndRearms(t *testing.T) {
	child := newFakeStages()
	child.statuses = map[string]string{
		"100": procStatus("1", routingCaps, "1000", "1000"),
		"101": procStatus("1", routingCaps, "1000", "1000"),
	}

	err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=4242"}))

	require.NoError(t, err)
	assert.Equal(t, []string{"pdeathsig"}, child.harden.calls, "the second stage drops nothing; it only re-arms")
	assert.Zero(t, child.execs)
}

func TestEnterHardened_SecondStageAcceptsARootKernelClass(t *testing.T) {
	def, err := DefinitionByName("datapath")
	require.NoError(t, err)
	child := newFakeStages()
	// CAP_NET_ADMIN and CAP_NET_RAW, as root: the uid is not the class's to
	// change, so a root uid is not a finding.
	child.statuses = map[string]string{"7": procStatus("1", "0000000000003000", "0", "0")}

	require.NoError(t, enterHardened(def, 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=4242"})))
}

func TestEnterHardened_SecondStageRefusesWhenTheSupervisorDiedAcrossTheExec(t *testing.T) {
	child := newFakeStages()
	child.harden.ppid = 1
	child.statuses = map[string]string{"100": procStatus("1", routingCaps, "1000", "1000")}

	err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=4242"}))

	var exited *ErrSupervisorExited
	require.ErrorAs(t, err, &exited)
	assert.Equal(t, 4242, exited.Parent)
}

func TestEnterHardened_SecondStageRejectsAMalformedMarker(t *testing.T) {
	child := newFakeStages()

	err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=supervisor"}))

	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	assert.Equal(t, "read the hardened-stage marker", hardening.Step)
	assert.Zero(t, child.statusReads)
	assert.Empty(t, child.harden.calls)
}

func TestEnterHardened_SecondStageRefusesWithoutThreadCredentials(t *testing.T) {
	for name, child := range map[string]*fakeStages{
		"read error": func() *fakeStages {
			child := newFakeStages()
			child.statusErr = unix.EACCES
			return child
		}(),
		"no threads": newFakeStages(),
	} {
		t.Run(name, func(t *testing.T) {
			err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=4242"}))

			var hardening *ErrHardening
			require.ErrorAs(t, err, &hardening)
			assert.Equal(t, "read the thread credentials", hardening.Step)
			assert.Empty(t, child.harden.calls, "nothing is re-armed for an unverified process")
		})
	}
}

func TestEnterHardened_SecondStageRejectsAThreadOutsideTheClass(t *testing.T) {
	cases := map[string]struct {
		status string
		field  string
	}{
		"no_new_privs unset":  {procStatus("0", routingCaps, "1000", "1000"), "NoNewPrivs"},
		"extra capability":    {procStatus("1", "0000000000001400", "1000", "1000"), "CapPrm"},
		"still root":          {procStatus("1", routingCaps, "0", "1000"), "Uid"},
		"root group":          {procStatus("1", routingCaps, "1000", "0"), "Gid"},
		"no capability field": {"Name:\tgatewayd\nNoNewPrivs:\t1\n", "CapPrm"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			child := newFakeStages()
			// The good thread sorts first, so the finding is the second one.
			child.statuses = map[string]string{
				"100": procStatus("1", routingCaps, "1000", "1000"),
				"200": tc.status,
			}

			err := enterHardened(routing(t), 1000, 1000, child.ops([]string{"GATEWAYD_HARDENED_PARENT=4242"}))

			var notHeld *ErrPrivilegeNotHeld
			require.ErrorAs(t, err, &notHeld)
			assert.Equal(t, "200", notHeld.Task)
			assert.Equal(t, tc.field, notHeld.Field)
			assert.Empty(t, child.harden.calls)
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

func TestLookupEnv(t *testing.T) {
	value, ok := lookupEnv([]string{"A=1", "GATEWAYD_HARDENED_PARENT=9"}, hardenedParentEnv)
	assert.True(t, ok)
	assert.Equal(t, "9", value)
}

func TestLookupEnv_PrefixOfAnotherKeyIsNotAMatch(t *testing.T) {
	_, ok := lookupEnv([]string{"GATEWAYD_HARDENED_PARENT_X=9"}, hardenedParentEnv)
	assert.False(t, ok)
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
