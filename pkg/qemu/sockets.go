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

package qemu

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// runtimeDirPattern names the per-run directory that holds the VM's unix
	// sockets. It lives under the system temp directory, not WorkDir, because
	// WorkDir can be arbitrarily deep and a unix socket path is capped by
	// sizeof(sockaddr_un.sun_path).
	runtimeDirPattern = "tp-vm-*"

	// qmpSocketName is the file name of the QMP socket inside the socket
	// directory.
	qmpSocketName = "qmp.sock"

	// SocketPathLimit is the longest unix socket path, in bytes, the kernel
	// accepts: sun_path is 108 bytes and must hold the terminating NUL.
	SocketPathLimit = 107
)

// ErrSocketPathTooLong is returned when a unix socket path exceeds
// SocketPathLimit, so QEMU would fail to bind it.
type ErrSocketPathTooLong struct {
	Path  string
	Limit int
}

func (e ErrSocketPathTooLong) Error() string {
	return fmt.Sprintf("unix socket path is %d bytes, limit is %d: %s", len(e.Path), e.Limit, e.Path)
}

// socketPath builds the path of a VM unix socket. It is the only place socket
// paths are derived: the per-run RuntimeDir when one exists, WorkDir otherwise.
func (c *Config) socketPath(name string) string {
	dir := c.RuntimeDir
	if dir == "" {
		dir = c.WorkDir
	}
	return filepath.Join(dir, name)
}

// checkSocketPath returns ErrSocketPathTooLong when path cannot be bound.
func checkSocketPath(path string) error {
	if len(path) > SocketPathLimit {
		return ErrSocketPathTooLong{Path: path, Limit: SocketPathLimit}
	}
	return nil
}

// validateSocketPaths checks every unix socket QEMU is asked to create.
func (c *Config) validateSocketPaths() error {
	paths := []string{c.GetQMPSocketPath(), c.GetConsoleSocketPath()}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := checkSocketPath(path); err != nil {
			return err
		}
	}
	return nil
}

// createRuntimeDir makes the short per-run socket directory unless the caller
// pinned the sockets (QMPSocketPath or RuntimeDir). The VM owns, and removes,
// only a directory it created.
func (vm *VM) createRuntimeDir() error {
	if vm.config.QMPSocketPath != "" || vm.config.RuntimeDir != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", runtimeDirPattern)
	if err != nil {
		return &WrappedError{Msg: "failed to create the VM socket directory", Err: err}
	}
	vm.runtimeDir = dir
	vm.config.RuntimeDir = dir
	return nil
}

// releaseRuntimeDir removes the socket directory this VM created. It is
// idempotent and the caller must hold vm.mu.
func (vm *VM) releaseRuntimeDir() {
	if vm.runtimeDir == "" {
		return
	}
	if err := os.RemoveAll(vm.runtimeDir); err != nil {
		vm.logger.Warnf("Failed to remove VM socket directory %s: %v", vm.runtimeDir, err)
	}
	vm.config.RuntimeDir = ""
	vm.runtimeDir = ""
}
