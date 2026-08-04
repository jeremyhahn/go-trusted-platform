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

//go:build linux

package podman

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPTY allocates a new pseudo-terminal pair via /dev/ptmx and returns the
// master and slave files. It uses the same unlockpt / ptsname ioctl sequence
// the container runtime relies on, implemented with golang.org/x/sys/unix so no
// external pty dependency is required.
func openPTY() (master *os.File, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "open /dev/ptmx", Err: err}
	}

	// Unlock the slave side (unlockpt): TIOCSPTLCK with a zero value.
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, nil, &WrappedError{Msg: "unlockpt", Err: err}
	}

	// Resolve the slave device number (ptsname): TIOCGPTN.
	ptn, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, nil, &WrappedError{Msg: "ptsname", Err: err}
	}

	slavePath := fmt.Sprintf("/dev/pts/%d", ptn)
	s, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, &WrappedError{Msg: "open pts slave", Err: err}
	}

	return m, s, nil
}

// ptySysProcAttr returns the process attributes that make the child create a
// new session and adopt its stdin (the pseudo-terminal slave, fd 0) as its
// controlling terminal.
func ptySysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}
}
