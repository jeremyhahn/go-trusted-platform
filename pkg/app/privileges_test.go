package app

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeOpError is the failure a fakeHost op returns when told to fail.
type fakeOpError struct{ op string }

func (e fakeOpError) Error() string { return "fake " + e.op + " failure" }

// fakeHost records every privilege and filesystem call so the tests never
// change the process credentials or touch the host.
type fakeHost struct {
	uid        int
	user       *user.User
	owner      [2]int
	notRegular bool
	failAt     string

	calls   []string
	groups  []int
	gid     int
	setUID  int
	path    string
	chownTo [2]int
	mode    os.FileMode
}

// newFakeHost is a host whose process runs as uid and whose log file, once
// created, is owned by root.
func newFakeHost(uid int) *fakeHost {
	return &fakeHost{
		uid:  uid,
		user: &user.User{Username: "platform", Uid: "65534", Gid: "65533"},
	}
}

func (f *fakeHost) record(op string) error {
	f.calls = append(f.calls, op)
	if f.failAt == op {
		return fakeOpError{op: op}
	}
	return nil
}

func (f *fakeHost) ops() hostOps {
	return hostOps{
		getuid: func() int { return f.uid },
		lookupUser: func(string) (*user.User, error) {
			if err := f.record("lookup"); err != nil {
				return nil, err
			}
			return f.user, nil
		},
		setgroups: func(gids []int) error { f.groups = gids; return f.record("setgroups") },
		setgid:    func(gid int) error { f.gid = gid; return f.record("setgid") },
		setuid:    func(uid int) error { f.setUID = uid; return f.record("setuid") },
		mkdirAll:  func(string, os.FileMode) error { return f.record("mkdir") },
		openLogFile: func(dir, name string, _ os.FileMode) (logFile, error) {
			f.path = filepath.Join(dir, name)
			if err := f.record("open"); err != nil {
				return nil, err
			}
			return fakeLogFile{host: f}, nil
		},
	}
}

// fakeLogFile records every descriptor operation on its fakeHost.
type fakeLogFile struct{ host *fakeHost }

func (l fakeLogFile) stat() (logFileStat, error) {
	if err := l.host.record("stat"); err != nil {
		return logFileStat{}, err
	}
	return logFileStat{regular: !l.host.notRegular, uid: l.host.owner[0], gid: l.host.owner[1]}, nil
}

func (l fakeLogFile) chown(uid, gid int) error {
	l.host.chownTo = [2]int{uid, gid}
	return l.host.record("chown")
}

func (l fakeLogFile) chmod(mode os.FileMode) error {
	l.host.mode = mode
	return l.host.record("chmod")
}

func (l fakeLogFile) close() error { return l.host.record("close") }

func newPrivilegeTestApp(logDir string) *App {
	return &App{Logger: logging.DefaultLogger(), RuntimeUser: "platform", LogDir: logDir}
}

func TestDropPrivileges_SwitchesToRuntimeUser(t *testing.T) {
	host := newFakeHost(0)
	app := newPrivilegeTestApp("/var/log/platform")

	require.NoError(t, app.dropPrivileges(host.ops()))

	assert.Equal(t, []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close", "setgroups", "setgid", "setuid"},
		host.calls, "the log file is prepared while still root, then groups and GID drop before the UID")
	assert.Equal(t, [2]int{65534, 65533}, host.chownTo, "the runtime user must own the log file it writes")
	assert.Equal(t, []int{65533}, host.groups, "root's supplementary groups must not survive the drop")
	assert.Equal(t, 65533, host.gid)
	assert.Equal(t, 65534, host.setUID)
	assert.Equal(t, "/var/log/platform", filepath.Dir(host.path))
}

func TestDropPrivileges_NoOp(t *testing.T) {
	tests := []struct {
		name        string
		uid         int
		runtimeUser string
	}{
		{name: "not running as root", uid: 1000, runtimeUser: "platform"},
		{name: "runtime user is root", uid: 0, runtimeUser: "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(tt.uid)
			app := newPrivilegeTestApp("")
			app.RuntimeUser = tt.runtimeUser

			require.NoError(t, app.dropPrivileges(host.ops()))
			assert.Empty(t, host.calls)
		})
	}
}

func TestDropPrivileges_InvalidLogDirFailsBeforeSetuid(t *testing.T) {
	host := newFakeHost(0)
	app := newPrivilegeTestApp("")

	err := app.dropPrivileges(host.ops())

	var target LogDirInvalidError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, []string{"lookup"}, host.calls,
		"an unusable LogDir must be refused before any filesystem call and the irreversible setuid")
}

func TestDropPrivileges_Errors(t *testing.T) {
	var numErr *strconv.NumError
	tests := []struct {
		name      string
		failAt    string
		uid, gid  string
		wantType  error
		wantCause any
		wantCalls []string
	}{
		{name: "user lookup", failAt: "lookup", wantType: RuntimeUserLookupError{},
			wantCalls: []string{"lookup"}},
		{name: "UID not a number", uid: "not-a-uid", wantType: RuntimeUserUIDError{}, wantCause: &numErr,
			wantCalls: []string{"lookup"}},
		{name: "UID negative", uid: "-1", wantType: RuntimeUserUIDError{}, wantCause: &numErr,
			wantCalls: []string{"lookup"}},
		{name: "UID reserved", uid: "4294967295", wantType: RuntimeUserUIDError{}, wantCause: &IDRangeError{},
			wantCalls: []string{"lookup"}},
		{name: "UID beyond 32 bits", uid: "4294967296", wantType: RuntimeUserUIDError{}, wantCause: &numErr,
			wantCalls: []string{"lookup"}},
		{name: "GID not a number", gid: "not-a-gid", wantType: RuntimeUserGIDError{}, wantCause: &numErr,
			wantCalls: []string{"lookup"}},
		{name: "GID negative", gid: "-5", wantType: RuntimeUserGIDError{}, wantCause: &numErr,
			wantCalls: []string{"lookup"}},
		{name: "GID reserved", gid: "4294967295", wantType: RuntimeUserGIDError{}, wantCause: &IDRangeError{},
			wantCalls: []string{"lookup"}},
		{name: "log dir create", failAt: "mkdir", wantType: LogDirCreateError{},
			wantCalls: []string{"lookup", "mkdir"}},
		{name: "log file open", failAt: "open", wantType: LogFileOpenError{},
			wantCalls: []string{"lookup", "mkdir", "open"}},
		{name: "log file stat", failAt: "stat", wantType: LogFileStatError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "close"}},
		{name: "log file chown", failAt: "chown", wantType: LogFileChownError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "close"}},
		{name: "log file chmod", failAt: "chmod", wantType: LogFileChmodError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close"}},
		{name: "log file close", failAt: "close", wantType: LogFileCloseError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close"}},
		{name: "setgroups", failAt: "setgroups", wantType: SetgroupsError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close", "setgroups"}},
		{name: "setgid", failAt: "setgid", wantType: SetgidError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close", "setgroups", "setgid"}},
		{name: "setuid", failAt: "setuid", wantType: SetuidError{},
			wantCalls: []string{"lookup", "mkdir", "open", "stat", "chown", "chmod", "close", "setgroups", "setgid", "setuid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(0)
			host.failAt = tt.failAt
			if tt.uid != "" {
				host.user.Uid = tt.uid
			}
			if tt.gid != "" {
				host.user.Gid = tt.gid
			}
			app := newPrivilegeTestApp("/var/log/platform")

			err := app.dropPrivileges(host.ops())

			require.Error(t, err)
			assertErrorType(t, err, tt.wantType)
			if tt.failAt != "" {
				assert.ErrorIs(t, err, fakeOpError{op: tt.failAt}, "the cause must stay reachable")
			} else {
				assert.ErrorAs(t, err, tt.wantCause, "the parse cause must stay reachable")
			}
			assert.Equal(t, tt.wantCalls, host.calls, "only the log file's close may run after a failed step")
		})
	}
}

// TestDropPrivileges_RootRuntimeUserIsNoOp exercises the exported entry
// point with RuntimeUser "root", which never changes credentials under any
// uid, so it is safe on a CI runner that runs as root.
func TestDropPrivileges_RootRuntimeUserIsNoOp(t *testing.T) {
	app := newPrivilegeTestApp("")
	app.RuntimeUser = "root"

	require.NoError(t, app.DropPrivileges())
}

func TestInitLogFile_ChownsWhenOwnerDiffers(t *testing.T) {
	tests := []struct {
		name     string
		owner    [2]int
		debug    bool
		wantMode os.FileMode
	}{
		{name: "owned by root", owner: [2]int{0, 0}, wantMode: 0644},
		{name: "owned by root in debug", owner: [2]int{0, 0}, debug: true, wantMode: os.ModePerm},
		{name: "only the group differs", owner: [2]int{1000, 0}, wantMode: 0644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(0)
			host.owner = tt.owner
			app := newPrivilegeTestApp("/var/log/platform")
			app.DebugFlag = tt.debug

			require.NoError(t, app.initLogFile(host.ops(), 1000, 1000))

			assert.Equal(t, []string{"mkdir", "open", "stat", "chown", "chmod", "close"}, host.calls)
			assert.Equal(t, [2]int{1000, 1000}, host.chownTo)
			assert.Equal(t, tt.wantMode, host.mode)
		})
	}
}

func TestInitLogFile_OwnerAlreadyMatches(t *testing.T) {
	tests := []struct {
		name  string
		owner [2]int
	}{
		{name: "root", owner: [2]int{0, 0}},
		{name: "runtime user", owner: [2]int{1000, 1000}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(1000)
			host.owner = tt.owner
			app := newPrivilegeTestApp("/var/log/platform")

			require.NoError(t, app.initLogFile(host.ops(), tt.owner[0], tt.owner[1]))

			assert.Equal(t, []string{"mkdir", "open", "stat", "chmod", "close"}, host.calls,
				"a file that already has the target owner must not be chowned")
			assert.Equal(t, os.FileMode(0644), host.mode)
			base := filepath.Base(host.path)
			assert.True(t, strings.HasSuffix(base, ".log") && base != ".log",
				"log file %q must have a name, not a hidden .log", host.path)
		})
	}
}

func TestInitLogFile_InvalidOwner(t *testing.T) {
	tests := []struct {
		name     string
		uid, gid int
	}{
		{name: "negative UID", uid: -1, gid: 0},
		{name: "negative GID", uid: 0, gid: -1},
		{name: "reserved UID", uid: maxID + 1, gid: 0},
		{name: "reserved GID", uid: 0, gid: maxID + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(0)
			app := newPrivilegeTestApp("/var/log/platform")

			err := app.initLogFile(host.ops(), tt.uid, tt.gid)

			var target LogFileOwnerError
			require.ErrorAs(t, err, &target)
			assert.Equal(t, LogFileOwnerError{UID: tt.uid, GID: tt.gid}, target)
			assert.Empty(t, host.calls, "the owner must be validated before any filesystem call")
		})
	}
}

func TestInitLogFile_InvalidLogDir(t *testing.T) {
	tests := []struct {
		name   string
		dir    string
		reason string
	}{
		{name: "empty", dir: "", reason: "empty"},
		{name: "whitespace", dir: "  \t", reason: "empty"},
		{name: "NUL byte", dir: "/var/log\x00/platform", reason: "contains a NUL byte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newFakeHost(0)
			app := newPrivilegeTestApp(tt.dir)

			err := app.initLogFile(host.ops(), 0, 0)

			var target LogDirInvalidError
			require.ErrorAs(t, err, &target)
			assert.Equal(t, tt.reason, target.Reason)
			assert.Empty(t, host.calls, "LogDir must be validated before any filesystem call")
		})
	}
}

func TestInitLogFile_Errors(t *testing.T) {
	tests := []struct {
		failAt    string
		wantType  error
		wantCalls []string
	}{
		{failAt: "mkdir", wantType: LogDirCreateError{}, wantCalls: []string{"mkdir"}},
		{failAt: "open", wantType: LogFileOpenError{}, wantCalls: []string{"mkdir", "open"}},
		{failAt: "stat", wantType: LogFileStatError{}, wantCalls: []string{"mkdir", "open", "stat", "close"}},
		{failAt: "chown", wantType: LogFileChownError{},
			wantCalls: []string{"mkdir", "open", "stat", "chown", "close"}},
		{failAt: "chmod", wantType: LogFileChmodError{},
			wantCalls: []string{"mkdir", "open", "stat", "chown", "chmod", "close"}},
		{failAt: "close", wantType: LogFileCloseError{},
			wantCalls: []string{"mkdir", "open", "stat", "chown", "chmod", "close"}},
	}
	for _, tt := range tests {
		t.Run(tt.failAt, func(t *testing.T) {
			host := newFakeHost(0)
			host.failAt = tt.failAt
			app := newPrivilegeTestApp("/var/log/platform")

			err := app.initLogFile(host.ops(), 1, 1)

			assertErrorType(t, err, tt.wantType)
			assert.ErrorIs(t, err, fakeOpError{op: tt.failAt})
			assert.Equal(t, tt.wantCalls, host.calls,
				"nothing but the close may run after a failed step, and an opened file is always closed")
		})
	}
}

func TestInitLogFile_RefusesNonRegularFile(t *testing.T) {
	host := newFakeHost(0)
	host.notRegular = true
	app := newPrivilegeTestApp("/var/log/platform")

	err := app.initLogFile(host.ops(), 1, 1)

	var target LogFileNotRegularError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, host.path, target.Path)
	assert.Equal(t, []string{"mkdir", "open", "stat", "close"}, host.calls,
		"a non-regular file must be neither chowned nor chmodded")
}

func TestInitLogFile_CreatesLogFile(t *testing.T) {
	tests := []struct {
		name     string
		debug    bool
		wantMode os.FileMode
	}{
		{name: "default", wantMode: 0644},
		{name: "debug", debug: true, wantMode: os.ModePerm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logDir := filepath.Join(t.TempDir(), "log")
			app := newPrivilegeTestApp(logDir)
			app.DebugFlag = tt.debug

			// The process's own UID and GID already own the file, so no chown
			// runs and the test needs no privilege.
			require.NoError(t, app.InitLogFile(os.Getuid(), os.Getgid()))

			entries, err := os.ReadDir(logDir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.True(t, strings.HasSuffix(entries[0].Name(), ".log"))
			info, err := entries[0].Info()
			require.NoError(t, err)
			assert.True(t, info.Mode().IsRegular())
			assert.Equal(t, tt.wantMode, info.Mode().Perm())
		})
	}
}

// TestInitLogFile_RefusesPlantedSymlink is the attack the descriptor-based
// hand-over closes: a link planted at the log path must not let root chmod
// (0777 in debug mode) or chown its target.
func TestInitLogFile_RefusesPlantedSymlink(t *testing.T) {
	logDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "shadow")
	require.NoError(t, os.WriteFile(target, nil, 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(logDir, logFileName())))
	app := newPrivilegeTestApp(logDir)
	app.DebugFlag = true

	err := app.InitLogFile(os.Getuid(), os.Getgid())

	var openErr LogFileOpenError
	require.ErrorAs(t, err, &openErr)
	assert.ErrorIs(t, err, syscall.ELOOP)
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "the symlink target's mode must be unchanged")
}

func TestInitLogFile_RefusesFIFO(t *testing.T) {
	logDir := t.TempDir()
	path := filepath.Join(logDir, logFileName())
	require.NoError(t, unix.Mkfifo(path, 0600))
	app := newPrivilegeTestApp(logDir)
	app.DebugFlag = true

	err := app.InitLogFile(os.Getuid(), os.Getgid())

	var target LogFileNotRegularError
	require.ErrorAs(t, err, &target)
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "a FIFO's mode must be unchanged")
}

func TestInitLogFile_EmptyLogDir(t *testing.T) {
	app := newPrivilegeTestApp("")

	err := app.InitLogFile(1, 1)

	var target LogDirInvalidError
	require.ErrorAs(t, err, &target)
}

func TestOpenLogFile(t *testing.T) {
	dir := t.TempDir()

	for _, attempt := range []string{"create", "reopen"} {
		file, err := openLogFile(dir, "platformd.log", 0600)
		require.NoError(t, err, attempt)

		st, err := file.stat()
		require.NoError(t, err, attempt)
		assert.Equal(t, logFileStat{regular: true, uid: os.Getuid(), gid: os.Getgid()}, st, attempt)
		require.NoError(t, file.chown(os.Getuid(), os.Getgid()), attempt)
		require.NoError(t, file.chmod(0640), attempt)
		require.NoError(t, file.close(), attempt)
	}

	info, err := os.Stat(filepath.Join(dir, "platformd.log"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm(), "the mode is applied through the descriptor")
}

func TestOpenLogFile_Errors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) string
		want  error
	}{
		{
			name:  "missing directory",
			setup: func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing") },
			want:  os.ErrNotExist,
		},
		{
			name: "symlinked file",
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "target")
				require.NoError(t, os.WriteFile(target, nil, 0600))
				require.NoError(t, os.Symlink(target, filepath.Join(dir, "platformd.log")))
				return dir
			},
			want: syscall.ELOOP,
		},
		{
			name: "symlinked directory",
			setup: func(t *testing.T, dir string) string {
				realDir := filepath.Join(dir, "real")
				require.NoError(t, os.Mkdir(realDir, 0700))
				link := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(realDir, link))
				return link
			},
			// O_DIRECTORY|O_NOFOLLOW on a symlink fails with ENOTDIR.
			want: syscall.ENOTDIR,
		},
		{
			name: "file instead of directory",
			setup: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "plain")
				require.NoError(t, os.WriteFile(path, nil, 0600))
				return path
			},
			want: syscall.ENOTDIR,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logDir := tt.setup(t, t.TempDir())

			file, err := openLogFile(logDir, "platformd.log", 0600)

			assert.Nil(t, file)
			assert.ErrorIs(t, err, tt.want, "a planted link must be refused, not followed")
		})
	}
}

func TestHostLogFile_ClosedDescriptor(t *testing.T) {
	file, err := openLogFile(t.TempDir(), "platformd.log", 0600)
	require.NoError(t, err)
	require.NoError(t, file.close())

	_, err = file.stat()
	var pathErr *os.PathError
	assert.ErrorAs(t, err, &pathErr)
	assert.Error(t, file.chown(os.Getuid(), os.Getgid()))
	assert.Error(t, file.chmod(0644))
	assert.ErrorIs(t, file.close(), os.ErrClosed)
}

func TestLogFileName(t *testing.T) {
	saved := Name
	t.Cleanup(func() { Name = saved })

	Name = "trusted-platform"
	assert.Equal(t, "trusted-platform.log", logFileName())

	Name = ""
	assert.Equal(t, "platformd.log", logFileName(), "an unset Name must not produce a hidden .log")
}

func TestParseID(t *testing.T) {
	for _, s := range []string{"0", "65534", "4294967294"} {
		id, err := parseID(s)
		require.NoError(t, err, s)
		assert.Equal(t, s, strconv.Itoa(id))
	}
}

func TestParseID_Invalid(t *testing.T) {
	var numErr *strconv.NumError
	tests := []struct {
		in        string
		wantCause any
	}{
		{in: "", wantCause: &numErr},
		{in: "-1", wantCause: &numErr},
		{in: "+1", wantCause: &numErr},
		{in: "abc", wantCause: &numErr},
		{in: "4294967296", wantCause: &numErr},
		{in: "4294967295", wantCause: &IDRangeError{}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := parseID(tt.in)

			assert.ErrorAs(t, err, tt.wantCause)
		})
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []int{0, 1000, maxID} {
		assert.True(t, validID(id), "%d", id)
	}
	for _, id := range []int{-1, maxID + 1} {
		assert.False(t, validID(id), "%d", id)
	}
}

func TestPrivilegeErrors_Messages(t *testing.T) {
	cause := fakeOpError{op: "cause"}
	tests := []struct {
		err  error
		want []string
	}{
		{RuntimeUserLookupError{User: "platform", Cause: cause}, []string{"platform", "not found"}},
		{RuntimeUserUIDError{User: "platform", UID: "x", Cause: cause}, []string{"platform", "UID", `"x"`}},
		{RuntimeUserGIDError{User: "platform", GID: "y", Cause: cause}, []string{"platform", "GID", `"y"`}},
		{SetgroupsError{GID: 7, Cause: cause}, []string{"setgroups([7])"}},
		{SetgidError{GID: 7, Cause: cause}, []string{"setgid(7)"}},
		{SetuidError{UID: 9, Cause: cause}, []string{"setuid(9)"}},
		{LogDirCreateError{Dir: "/l", Cause: cause}, []string{"create log directory", "/l"}},
		{LogFileOpenError{Path: "/l/p.log", Cause: cause}, []string{"open log file", "/l/p.log"}},
		{LogFileStatError{Path: "/l/p.log", Cause: cause}, []string{"owner of log file", "/l/p.log"}},
		{LogFileChownError{Path: "/l/p.log", UID: 1, GID: 2, Cause: cause}, []string{"chown", "1:2"}},
		{LogFileChmodError{Path: "/l/p.log", Mode: 0644, Cause: cause}, []string{"chmod", "-rw-r--r--"}},
		{LogFileCloseError{Path: "/l/p.log", Cause: cause}, []string{"close log file", "/l/p.log"}},
	}
	for _, tt := range tests {
		msg := tt.err.Error()
		for _, want := range tt.want {
			assert.Contains(t, msg, want)
		}
		assert.Contains(t, msg, cause.Error(), "%T must carry its cause", tt.err)
		assert.ErrorIs(t, tt.err, cause, "%T must unwrap to its cause", tt.err)
	}
}

func TestPrivilegeErrors_MessagesWithoutCause(t *testing.T) {
	tests := []struct {
		err  error
		want []string
	}{
		{LogDirInvalidError{Dir: "", Reason: "empty"}, []string{"log directory", "empty"}},
		{LogFileOwnerError{UID: -1, GID: 5}, []string{"-1:5", "0..4294967294"}},
		{LogFileNotRegularError{Path: "/l/p.log"}, []string{"/l/p.log", "not a regular file"}},
		{IDRangeError{ID: 4294967295}, []string{"4294967295", "0..4294967294"}},
	}
	for _, tt := range tests {
		msg := tt.err.Error()
		for _, want := range tt.want {
			assert.Contains(t, msg, want)
		}
	}
}

// assertErrorType asserts err's chain holds an error of want's concrete type.
func assertErrorType(t *testing.T, err error, want error) {
	t.Helper()
	for e := err; e != nil; e = errors.Unwrap(e) {
		if reflect.TypeOf(e) == reflect.TypeOf(want) {
			return
		}
	}
	t.Fatalf("error %v (%T) is not a %T", err, err, want)
}
