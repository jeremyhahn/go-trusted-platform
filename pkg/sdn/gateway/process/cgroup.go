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
	"strconv"
	"strings"
)

// DefaultCgroupRoot is the cgroup v2 mount point on Alpine and every other
// unified-hierarchy distribution.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// CgroupManager creates one cgroup v2 leaf per child process under a parent
// directory, writes the class's limits into it, and hands the supervisor an
// open directory descriptor so the kernel places the child in the leaf at
// clone time rather than after it is already running.
type CgroupManager struct {
	// Root is the cgroup v2 mount point; empty means DefaultCgroupRoot.
	Root string
	// Parent is the directory under Root that holds one leaf per process,
	// e.g. "gatewayd.slice". Empty disables cgroup placement entirely,
	// which is what a developer machine and the unit tests use.
	Parent string
}

// Enabled reports whether leaves will be created. It takes a nil receiver,
// and so do Prepare and Remove, which check it first: a nil manager is the
// documented way to disable placement (Config.Cgroups).
func (m *CgroupManager) Enabled() bool {
	return m != nil && m.Parent != ""
}

// root resolves the mount point.
func (m *CgroupManager) root() string {
	if m.Root != "" {
		return m.Root
	}
	return DefaultCgroupRoot
}

// leafPath is where one process's leaf lives. The process name comes from
// this package's class table, and filepath.Base keeps a future table entry
// from escaping the parent directory.
func (m *CgroupManager) leafPath(process string) string {
	return filepath.Join(m.root(), m.Parent, filepath.Base(process))
}

// Prepare creates the leaf for a process, delegates the memory and cpu
// controllers down to it, writes memory.max and cpu.max from the definition,
// and returns the open leaf directory. The caller passes its
// descriptor to the launcher and closes the directory once the child is
// running; returning the *os.File rather than a bare descriptor keeps the
// file from being finalized — and the descriptor from being closed — while
// the child is still being cloned into it.
//
// A disabled manager returns a nil file and no error: cgroup placement is a
// hardening step, and a host without a writable cgroup tree still runs the
// process model.
func (m *CgroupManager) Prepare(def Definition) (*os.File, error) {
	if !m.Enabled() {
		return nil, nil
	}
	path := m.leafPath(def.Name)
	if err := os.MkdirAll(path, 0o750); err != nil {
		return nil, &ErrCgroup{Path: path, Op: "create", Cause: err}
	}
	if err := m.delegate(def); err != nil {
		return nil, err
	}
	if def.MemoryMax > 0 {
		if err := m.write(path, "memory.max", strconv.FormatInt(def.MemoryMax, 10)); err != nil {
			return nil, err
		}
	}
	if def.CPUMax != "" {
		if err := m.write(path, "cpu.max", def.CPUMax); err != nil {
			return nil, err
		}
	}
	// The path is the configured root and parent joined with a process name
	// from the class table in this package — never operator input.
	leaf, err := os.Open(path) // #nosec G304 -- path is built from the class table, not from input
	if err != nil {
		return nil, &ErrCgroup{Path: path, Op: "open", Cause: err}
	}
	return leaf, nil
}

// delegate enables the controllers a definition's limits need in the
// cgroup.subtree_control of every directory of Parent, top down. A cgroup v2
// leaf only carries memory.max or cpu.max once its parent enables that
// controller for its children, and a fresh directory enables none, so
// without this the first limit write fails. Root's own subtree_control is
// the host's (systemd's, or the container runtime's) and is left alone.
// Enabling a controller that is already enabled is a no-op in the kernel,
// so a restart rewrites the same value harmlessly.
func (m *CgroupManager) delegate(def Definition) error {
	var controllers []string
	if def.MemoryMax > 0 {
		controllers = append(controllers, "+memory")
	}
	if def.CPUMax != "" {
		controllers = append(controllers, "+cpu")
	}
	if len(controllers) == 0 {
		return nil
	}
	value := strings.Join(controllers, " ")
	dir := m.root()
	for _, component := range strings.Split(filepath.Clean(m.Parent), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		dir = filepath.Join(dir, component)
		if err := m.write(dir, "cgroup.subtree_control", value); err != nil {
			return err
		}
	}
	return nil
}

// write sets one cgroup attribute.
func (m *CgroupManager) write(path, attribute, value string) error {
	file := filepath.Join(path, attribute)
	// The interface files of a real leaf already exist and keep their own
	// mode; this one applies only where they do not.
	if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
		return &ErrCgroup{Path: file, Op: "write", Cause: err}
	}
	return nil
}

// Remove deletes a process's leaf. An already absent leaf is not an error;
// a leaf with live processes in it is, and the supervisor logs it rather
// than retrying, because that means a child outlived its own teardown.
func (m *CgroupManager) Remove(process string) error {
	if !m.Enabled() {
		return nil
	}
	path := m.leafPath(process)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &ErrCgroup{Path: path, Op: "remove", Cause: err}
	}
	return nil
}
