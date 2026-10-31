package process

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

// errFchownRefused is the owner change a test refuses.
var errFchownRefused = errors.New("fchown refused")

// fchownCall is one owner change a test recorded instead of making it.
type fchownCall struct {
	inode    uint64
	uid, gid int
}

// recordFchown replaces the supervisor's owner change with one that records
// the inode it was asked to change, so no test changes an owner on the host.
func recordFchown(t *testing.T, supervisor *Supervisor) *[]fchownCall {
	t.Helper()
	var calls []fchownCall
	supervisor.fchown = func(fd, uid, gid int) error {
		var st unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &st))
		calls = append(calls, fchownCall{inode: st.Ino, uid: uid, gid: gid})
		return nil
	}
	return &calls
}

// vpnSupervisor is a supervisor whose data directory is dataDir, with the
// test's own credentials as the service account.
func vpnSupervisor(t *testing.T, dataDir string) (*Supervisor, *fakeLauncher) {
	t.Helper()
	supervisor, launcher, _ := newSupervisor(t, func(cfg *Config) {
		cfg.Inherited.DataDir = dataDir
		cfg.UID, cfg.GID = uint32(os.Getuid()), uint32(os.Getgid())
	})
	return supervisor, launcher
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Lstat(path, &st))
	return st.Ino
}

func TestStartService_TheJournalARootGatewayLeftIsHandedToTheVPNChild(t *testing.T) {
	// An unsupervised gatewayd ran as root and journaled two revocations
	// the control plane had not taken. Supervised, the vpn child reads that
	// journal as the service account; it is handed over before the launch,
	// with its revocations (Codex 7994, #557).
	dataDir := t.TempDir()
	stateDir := filepath.Join(dataDir, "vpn")
	require.NoError(t, os.Mkdir(stateDir, 0o700))
	journal := filepath.Join(stateDir, gateway.VPNRevocationJournalFile)
	pending := map[string]string{"lease-a": "tenant-1", "lease-b": "tenant-2"}
	data, err := json.Marshal(pending)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journal, data, 0o600))
	supervisor, launcher := vpnSupervisor(t, dataDir)
	calls := recordFchown(t, supervisor)

	require.NoError(t, supervisor.StartService(testContext(t), gateway.ServiceManagementVPN))

	assert.Equal(t, []fchownCall{{inode: inode(t, journal), uid: os.Getuid(), gid: os.Getgid()}}, *calls,
		"the journal itself is given to the service account")
	var st unix.Stat_t
	require.NoError(t, unix.Stat(journal, &st))
	assert.Equal(t, uint32(stateFileMode), st.Mode&0o7777)
	kept, err := os.ReadFile(journal)
	require.NoError(t, err)
	var revoked map[string]string
	require.NoError(t, json.Unmarshal(kept, &revoked))
	assert.Equal(t, pending, revoked, "a revoked lease stays out after the child's rebuild")
	assert.Equal(t, 1, launcher.launchCount())
}

func TestStartService_ASymlinkedJournalRefusesTheLaunch(t *testing.T) {
	// A symlink under the journal's name would hand its target, any file
	// root can change, to the service account.
	dataDir := t.TempDir()
	stateDir := filepath.Join(dataDir, "vpn")
	require.NoError(t, os.Mkdir(stateDir, 0o700))
	target := filepath.Join(dataDir, "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
	journal := filepath.Join(stateDir, gateway.VPNRevocationJournalFile)
	require.NoError(t, os.Symlink(target, journal))
	supervisor, launcher := vpnSupervisor(t, dataDir)
	calls := recordFchown(t, supervisor)

	err := supervisor.StartService(testContext(t), gateway.ServiceManagementVPN)
	var stateErr *ErrStateDir
	require.ErrorAs(t, err, &stateErr)
	assert.Equal(t, "hand over", stateErr.Op)
	assert.Equal(t, journal, stateErr.Path)
	var symlink *ErrStateFileSymlink
	require.ErrorAs(t, err, &symlink)
	assert.Equal(t, journal, symlink.Path)
	assert.Empty(t, *calls, "nothing is given away")
	assert.Zero(t, launcher.launchCount(), "the child is not started with a journal it cannot trust")
}

func TestStartService_AVPNChildWithNoJournalStartsClean(t *testing.T) {
	// The first supervised start: there is nothing to hand over, and the
	// child creates the journal itself on its first revocation.
	dataDir := t.TempDir()
	supervisor, launcher := vpnSupervisor(t, dataDir)
	calls := recordFchown(t, supervisor)

	require.NoError(t, supervisor.StartService(testContext(t), gateway.ServiceManagementVPN))

	assert.Empty(t, *calls)
	_, err := os.Lstat(filepath.Join(dataDir, "vpn", gateway.VPNRevocationJournalFile))
	assert.ErrorIs(t, err, os.ErrNotExist, "no journal is made for the child")
	assert.Equal(t, 1, launcher.launchCount())
}

func TestHandOverStateFile_TightensTheModeAndKeepsTheContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.WriteFile(path, []byte("kept"), 0o644))
	var owner []int
	fchown := func(_, uid, gid int) error {
		owner = append(owner, uid, gid)
		return nil
	}

	require.NoError(t, handOverStateFile(path, 4242, 4343, fchown))

	assert.Equal(t, []int{4242, 4343}, owner)
	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))
	assert.Equal(t, uint32(0o600), st.Mode&0o7777)
	kept, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "kept", string(kept))
}

func TestHandOverStateFile_RefusesWhatIsNotTheStateFile(t *testing.T) {
	neverCalled := func(t *testing.T) func(int, int, int) error {
		return func(int, int, int) error {
			t.Error("fchown called on a refused file")
			return nil
		}
	}
	t.Run("a FIFO", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		require.NoError(t, unix.Mkfifo(path, 0o600))
		err := handOverStateFile(path, 1, 1, neverCalled(t))
		var notRegular *ErrStateFileNotRegular
		require.ErrorAs(t, err, &notRegular)
		assert.Equal(t, path, notRegular.Path)
		assert.Equal(t, uint32(unix.S_IFIFO), notRegular.Mode&unix.S_IFMT)
	})
	t.Run("a directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		require.NoError(t, os.Mkdir(path, 0o700))
		var notRegular *ErrStateFileNotRegular
		require.ErrorAs(t, handOverStateFile(path, 1, 1, neverCalled(t)), &notRegular)
	})
	t.Run("a file with a second hard link", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(dir, "outside")
		require.NoError(t, os.WriteFile(outside, nil, 0o600))
		path := filepath.Join(dir, "state")
		require.NoError(t, os.Link(outside, path))
		err := handOverStateFile(path, 1, 1, neverCalled(t))
		var linked *ErrStateFileLinked
		require.ErrorAs(t, err, &linked)
		assert.Equal(t, uint64(2), linked.Links)
	})
	t.Run("a parent that is a file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(parent, nil, 0o600))
		err := handOverStateFile(filepath.Join(parent, "state"), 1, 1, neverCalled(t))
		assert.ErrorIs(t, err, unix.ENOTDIR)
	})
}

func TestHandOverStateFile_ARefusedOwnerChangeIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	err := handOverStateFile(path, 1, 1, func(int, int, int) error { return errFchownRefused })

	assert.ErrorIs(t, err, errFchownRefused)
	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))
	assert.Equal(t, uint32(0o644), st.Mode&0o7777, "the mode is left for the next attempt")
}
