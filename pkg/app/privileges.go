package app

import (
	"errors"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxID is the largest usable UID or GID. uid_t and gid_t are 32 bits and
// the kernel reserves 4294967295 ((uid_t)-1) to mean "leave unchanged", so
// chown and setuid would silently ignore it instead of applying it.
const maxID = math.MaxUint32 - 1

// hostOps is the operating-system surface InitLogFile and DropPrivileges
// act through. Production uses hostPrivilegeOps; tests substitute fakes so
// no test changes the process credentials or touches the host filesystem.
type hostOps struct {
	getuid      func() int
	lookupUser  func(name string) (*user.User, error)
	setgroups   func(gids []int) error
	setgid      func(gid int) error
	setuid      func(uid int) error
	mkdirAll    func(path string, perm os.FileMode) error
	openLogFile func(dir, name string, perm os.FileMode) (logFile, error)
}

var hostPrivilegeOps = hostOps{
	getuid:      syscall.Getuid,
	lookupUser:  user.Lookup,
	setgroups:   syscall.Setgroups,
	setgid:      syscall.Setgid,
	setuid:      syscall.Setuid,
	mkdirAll:    os.MkdirAll,
	openLogFile: openLogFile,
}

// logFile is the open log file DropPrivileges hands to the runtime user.
// Its owner and mode are read and changed through the descriptor, never by
// path: the process is still root, and a path resolved again after the open
// could name a symlink swapped in since, making root chown or chmod its
// target.
type logFile interface {
	stat() (logFileStat, error)
	chown(uid, gid int) error
	chmod(mode os.FileMode) error
	close() error
}

// logFileStat is what initLogFile needs to know about the open log file.
type logFileStat struct {
	regular  bool
	uid, gid int
}

// hostLogFile is a logFile backed by an open descriptor.
type hostLogFile struct {
	file *os.File
}

func (f hostLogFile) stat() (logFileStat, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &st); err != nil {
		return logFileStat{}, &os.PathError{Op: "fstat", Path: f.file.Name(), Err: err}
	}
	return logFileStat{
		regular: st.Mode&unix.S_IFMT == unix.S_IFREG,
		uid:     int(st.Uid),
		gid:     int(st.Gid),
	}, nil
}

func (f hostLogFile) chown(uid, gid int) error { return f.file.Chown(uid, gid) }

func (f hostLogFile) chmod(mode os.FileMode) error { return f.file.Chmod(mode) }

func (f hostLogFile) close() error { return f.file.Close() }

// openLogFile opens name inside dir for appending, creating it with perm if
// missing. Neither dir nor name may be a symlink: dir is opened with
// O_DIRECTORY|O_NOFOLLOW and name is opened relative to that descriptor with
// O_NOFOLLOW, so a link planted at either is refused (ELOOP or ENOTDIR)
// rather than followed by root.
func openLogFile(dir, name string, perm os.FileMode) (logFile, error) {
	dir = filepath.Clean(dir)
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	path := filepath.Join(dir, name)
	fd, openErr := unix.Openat(dirFD, name,
		unix.O_RDWR|unix.O_CREAT|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	closeErr := unix.Close(dirFD)
	if openErr != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: openErr}
	}
	file := os.NewFile(uintptr(fd), path)
	if closeErr != nil {
		return nil, errors.Join(&os.PathError{Op: "close", Path: dir, Err: closeErr}, file.Close())
	}
	return hostLogFile{file: file}, nil
}

// logFileName is the platform log file's name. Name is ldflag-populated and
// is empty on a bare `go build`, which would produce a hidden ".log" file,
// so it falls back to a stable name the OpenRC init script and operators
// can find.
func logFileName() string {
	if Name == "" {
		return "platformd.log"
	}
	return Name + ".log"
}

// InitLogFile creates the platform log file under LogDir and makes it
// uid:gid's: the file is chowned when its owner differs, and its mode is set
// (0644, or 0777 in debug mode). Only the file changes hands; the directory
// stays as the operator made it, because --log-dir may name a shared
// directory such as /var/log. Whether the process may chown is the kernel's
// decision (root, or CAP_CHOWN); a refusal is a LogFileChownError, since the
// runtime user could not write the log.
func (app *App) InitLogFile(uid, gid int) error {
	return app.initLogFile(hostPrivilegeOps, uid, gid)
}

func (app *App) initLogFile(ops hostOps, uid, gid int) (err error) {
	if err := validateLogDir(app.LogDir); err != nil {
		return err
	}
	if !validID(uid) || !validID(gid) {
		return LogFileOwnerError{UID: uid, GID: gid}
	}
	path := filepath.Join(app.LogDir, logFileName())
	if err := ops.mkdirAll(app.LogDir, os.ModePerm); err != nil {
		return LogDirCreateError{Dir: app.LogDir, Cause: err}
	}
	file, err := ops.openLogFile(app.LogDir, logFileName(), 0600)
	if err != nil {
		return LogFileOpenError{Path: path, Cause: err}
	}
	defer func() {
		if closeErr := file.close(); closeErr != nil && err == nil {
			err = LogFileCloseError{Path: path, Cause: closeErr}
		}
	}()
	return app.handOverLogFile(file, path, uid, gid)
}

// handOverLogFile makes the open log file a regular file owned by uid:gid
// with the configured mode. It refuses anything but a regular file: a FIFO
// or device node planted under the log name is not root's to chown.
func (app *App) handOverLogFile(file logFile, path string, uid, gid int) error {
	st, err := file.stat()
	if err != nil {
		return LogFileStatError{Path: path, Cause: err}
	}
	if !st.regular {
		return LogFileNotRegularError{Path: path}
	}
	if st.uid != uid || st.gid != gid {
		if err := file.chown(uid, gid); err != nil {
			return LogFileChownError{Path: path, UID: uid, GID: gid, Cause: err}
		}
	}
	perm := os.FileMode(0644)
	if app.DebugFlag {
		perm = os.ModePerm
	}
	if err := file.chmod(perm); err != nil {
		return LogFileChmodError{Path: path, Mode: perm, Cause: err}
	}
	return nil
}

// validateLogDir rejects a log directory that cannot name a directory,
// before any filesystem call: an empty LogDir would put the log file at
// "/platformd.log".
func validateLogDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return LogDirInvalidError{Dir: dir, Reason: "empty"}
	}
	if strings.ContainsRune(dir, 0) {
		return LogDirInvalidError{Dir: dir, Reason: "contains a NUL byte"}
	}
	return nil
}

// validID reports whether id is a UID or GID the kernel will apply.
func validID(id int) bool {
	return id >= 0 && int64(id) <= maxID
}

// parseID parses a UID or GID from the user database. A sign, a value
// beyond 32 bits, or the reserved maxID+1 is refused: ParseInt accepted
// "-1", which setuid and chown read as "leave unchanged".
func parseID(s string) (int, error) {
	id, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	if id > maxID {
		return 0, IDRangeError{ID: id}
	}
	return int(id), nil
}

// DropPrivileges switches a process started as root to RuntimeUser. The
// log file is prepared first, while the process is still root: after setuid
// it could neither create the file in a root-owned directory nor hand it to
// the runtime user. Then the supplementary groups are reduced to the user's
// primary group, and the GID and UID are changed. It is a no-op off Linux,
// when not running as root, or when RuntimeUser is "root".
func (app *App) DropPrivileges() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return app.dropPrivileges(hostPrivilegeOps)
}

func (app *App) dropPrivileges(ops hostOps) error {
	if ops.getuid() != 0 || app.RuntimeUser == "root" {
		return nil
	}
	app.Logger.Debugf("Running as root, downgrading to user %s", app.RuntimeUser)
	runtimeUser, err := ops.lookupUser(app.RuntimeUser)
	if err != nil {
		return RuntimeUserLookupError{User: app.RuntimeUser, Cause: err}
	}
	uid, err := parseID(runtimeUser.Uid)
	if err != nil {
		return RuntimeUserUIDError{User: app.RuntimeUser, UID: runtimeUser.Uid, Cause: err}
	}
	gid, err := parseID(runtimeUser.Gid)
	if err != nil {
		return RuntimeUserGIDError{User: app.RuntimeUser, GID: runtimeUser.Gid, Cause: err}
	}
	if err := app.initLogFile(ops, uid, gid); err != nil {
		return err
	}
	if err := ops.setgroups([]int{gid}); err != nil {
		return SetgroupsError{GID: gid, Cause: err}
	}
	if err := ops.setgid(gid); err != nil {
		return SetgidError{GID: gid, Cause: err}
	}
	if err := ops.setuid(uid); err != nil {
		return SetuidError{UID: uid, Cause: err}
	}
	return nil
}
