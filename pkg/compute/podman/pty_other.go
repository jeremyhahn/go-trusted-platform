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

//go:build !linux

package podman

import (
	"errors"
	"os"
	"syscall"
)

// ErrPTYUnsupported is returned when pseudo-terminal allocation is attempted on
// a platform without the Linux /dev/ptmx interface. Container exec/attach are a
// Linux-only capability of the trusted platform.
var ErrPTYUnsupported = errors.New("pseudo-terminal allocation is only supported on linux")

// openPTY is unsupported on non-Linux platforms.
func openPTY() (master *os.File, slave *os.File, err error) {
	return nil, nil, ErrPTYUnsupported
}

// ptySysProcAttr returns nil on non-Linux platforms; the pty path is never
// reached because openPTY fails first.
func ptySysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
