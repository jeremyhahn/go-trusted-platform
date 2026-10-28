package process

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// stateFileMode is the mode a handed-over state file keeps: the process's
// own, as the vpn child's revocation journal is written.
const stateFileMode = 0o600

// handOverStateFiles gives each of def.StateFiles under dir to the
// credentials the process runs with. A gatewayd that ran unsupervised, as
// root, wrote them root-owned with mode 0600; the unprivileged child could
// not read them, and the vpn child would not start (Codex 7994, #557). A
// file that does not exist yet is the child's to create.
func (s *Supervisor) handOverStateFiles(def Definition, dir string) error {
	for _, name := range def.StateFiles {
		path := filepath.Join(dir, name)
		if err := handOverStateFile(path, s.cfg.UID, s.cfg.GID, s.fchown); err != nil {
			return &ErrStateDir{Process: def.Name, Path: path, Op: "hand over", Cause: err}
		}
	}
	return nil
}

// handOverStateFile changes path's owner to uid:gid and its mode to
// stateFileMode, through a handle opened without following a symlink, so
// what is changed is the file that was checked. A symlink, anything but a
// regular file, and a file with another hard link are refused: each would
// hand the child a file outside its state directory.
func handOverStateFile(path string, uid, gid uint32, fchown func(fd, uid, gid int) error) error {
	// O_NONBLOCK so a FIFO planted under the name does not block the open.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if errors.Is(err, unix.ELOOP) {
		return &ErrStateFileSymlink{Path: path}
	}
	if err != nil {
		return err
	}
	return errors.Join(handOverOpenStateFile(fd, path, uid, gid, fchown), unix.Close(fd))
}

// handOverOpenStateFile checks and changes the file open as fd.
func handOverOpenStateFile(fd int, path string, uid, gid uint32, fchown func(fd, uid, gid int) error) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return &ErrStateFileNotRegular{Path: path, Mode: st.Mode}
	}
	if st.Nlink != 1 {
		return &ErrStateFileLinked{Path: path, Links: uint64(st.Nlink)}
	}
	if err := fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	return unix.Fchmod(fd, stateFileMode)
}
