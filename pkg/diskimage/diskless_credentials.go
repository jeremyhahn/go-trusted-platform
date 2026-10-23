package diskimage

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// disklessShadowFiles are the files in the root that carry password hashes:
// the shadow file and the backup the account tools leave beside it.
var disklessShadowFiles = []string{"etc/shadow", "etc/shadow-"}

// shadowLocked is the password field of an account nobody can log in to with a
// password.
const shadowLocked = "!"

// DisklessRootCredentialError reports an account in a diskless root that still
// has a usable password hash (or none at all). The root is served to every node
// and to anyone who can fetch the image, so a password in it is a password
// everyone holds. Credentials are per node and come after attestation.
type DisklessRootCredentialError struct {
	// Path is relative to the root.
	Path string
	// Account is the login name.
	Account string
}

func (e DisklessRootCredentialError) Error() string {
	return "diskless root: /" + e.Path + ": account " + e.Account + " has a usable password; the root is public"
}

// usableShadowHash reports whether a shadow password field lets a login
// through: anything not locked with a leading "!" or "*", which includes an
// empty field (no password required).
func usableShadowHash(field string) bool {
	return !strings.HasPrefix(field, "!") && !strings.HasPrefix(field, "*")
}

// lockRootAccounts locks every account in the root's shadow files that has a
// usable password, so the installer's root password is not packed into the
// public image.
func lockRootAccounts(root string) error {
	for _, rel := range disklessShadowFiles {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		locked := rewriteShadow(data)
		if err := os.WriteFile(path, locked, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// rewriteShadow sets the password field of every usable entry to shadowLocked.
// Lines that are not shadow entries pass through untouched.
func rewriteShadow(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		fields := bytes.SplitN(line, []byte(":"), 3)
		if len(fields) < 3 || len(fields[0]) == 0 {
			continue
		}
		if usableShadowHash(string(fields[1])) {
			lines[i] = bytes.Join([][]byte{fields[0], []byte(shadowLocked), fields[2]}, []byte(":"))
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

// refuseRootCredentials refuses the first account in the root's shadow files
// that still has a usable password.
func refuseRootCredentials(root string) error {
	for _, rel := range disklessShadowFiles {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.SplitN(line, ":", 3)
			if len(fields) < 3 || fields[0] == "" {
				continue
			}
			if usableShadowHash(fields[1]) {
				return DisklessRootCredentialError{Path: rel, Account: fields[0]}
			}
		}
	}
	return nil
}
