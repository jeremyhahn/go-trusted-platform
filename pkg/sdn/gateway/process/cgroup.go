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
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fsnotify/fsnotify"
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
	// The class table sets no swap limit, so a leaf reused by a relaunch gets
	// the kernel default back: a swap limit left on it would otherwise
	// survive into the successor. The file exists only with swap accounting.
	swapMax := filepath.Join(path, "memory.swap.max")
	if _, err := os.Stat(swapMax); err == nil {
		if err := m.write(path, "memory.swap.max", "max"); err != nil {
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

// Remove deletes a process's leaf once the kernel reports it empty. An
// already absent leaf is not an error.
//
// A reaped child is not yet gone from its leaf: the kernel unlinks an
// exiting task from its cgroup after the task's last context switch, which
// can come after the parent's wait returns, and until then rmdir fails with
// EBUSY. Remove therefore waits for "populated 0" in the leaf's cgroup.events
// — the kernel raises a modify event on that file when the value changes —
// and only then removes the directory. A leaf still populated when ctx ends
// is an error, and the supervisor logs it rather than retrying, because that
// means a child outlived its own teardown.
func (m *CgroupManager) Remove(ctx context.Context, process string) error {
	if !m.Enabled() {
		return nil
	}
	path := m.leafPath(process)
	if err := awaitEmpty(ctx, path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &ErrCgroup{Path: path, Op: "remove", Cause: err}
	}
	return nil
}

// awaitEmpty returns once the leaf at path holds no process. A leaf, or a
// cgroup.events file, that does not exist holds nothing to wait for.
func awaitEmpty(ctx context.Context, path string) (err error) {
	events := filepath.Join(path, "cgroup.events")
	if _, statErr := os.Stat(events); os.IsNotExist(statErr) {
		return nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return &ErrCgroup{Path: events, Op: "watch", Cause: err}
	}
	defer func() {
		if closeErr := watcher.Close(); closeErr != nil && err == nil {
			err = &ErrCgroup{Path: events, Op: "watch", Cause: closeErr}
		}
	}()
	// The watch is in place before the first read, so a change between the
	// read and the select is not missed.
	if err := watcher.Add(events); err != nil {
		if os.IsNotExist(err) {
			return nil // the leaf was removed meanwhile
		}
		return &ErrCgroup{Path: events, Op: "watch", Cause: err}
	}
	for {
		counters, err := readKeyed(events)
		if err != nil {
			return err
		}
		populated, err := counters.value(events, "populated")
		if err != nil {
			return err
		}
		if populated == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return &ErrCgroup{Path: events, Op: "await empty", Cause: ctx.Err()}
		case _, ok := <-watcher.Events:
			if !ok {
				return &ErrCgroup{Path: events, Op: "watch", Cause: fsnotify.ErrClosed}
			}
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				watchErr = fsnotify.ErrClosed
			}
			return &ErrCgroup{Path: events, Op: "watch", Cause: watchErr}
		}
	}
}

// MemoryUsage is a leaf's memory accounting as the kernel reports it. The
// counters belong to the leaf, not to one child: Peak and the event counts
// carry over a relaunch into the same leaf.
type MemoryUsage struct {
	// Current is memory.current, the bytes charged to the leaf now.
	Current int64
	// Peak is memory.peak, the most bytes ever charged to the leaf.
	Peak int64
	// HasPeak is false on a kernel without memory.peak (before 5.19); Peak
	// is then zero and means nothing.
	HasPeak bool
	// Max counts memory.events "max": allocations that hit memory.max.
	Max int64
	// OOM counts memory.events "oom": allocations that failed at the limit.
	OOM int64
	// OOMKill counts memory.events "oom_kill": processes the kernel's OOM
	// killer ended inside the leaf.
	OOMKill int64
}

// Memory reads a process's leaf accounting: memory.current, memory.peak and
// the memory.events counters. A disabled manager accounts nothing and
// returns the zero value.
func (m *CgroupManager) Memory(process string) (MemoryUsage, error) {
	if !m.Enabled() {
		return MemoryUsage{}, nil
	}
	path := m.leafPath(process)
	current, err := readCounter(filepath.Join(path, "memory.current"))
	if err != nil {
		return MemoryUsage{}, err
	}
	// memory.peak arrived in Linux 5.19; an older kernel has no such file,
	// which is no reason to lose the rest of the accounting.
	usage := MemoryUsage{Current: current}
	peakFile := filepath.Join(path, "memory.peak")
	if _, statErr := os.Stat(peakFile); !os.IsNotExist(statErr) {
		if usage.Peak, err = readCounter(peakFile); err != nil {
			return MemoryUsage{}, err
		}
		usage.HasPeak = true
	}
	file := filepath.Join(path, "memory.events")
	counters, err := readKeyed(file)
	if err != nil {
		return MemoryUsage{}, err
	}
	for key, field := range map[string]*int64{"max": &usage.Max, "oom": &usage.OOM, "oom_kill": &usage.OOMKill} {
		if *field, err = counters.value(file, key); err != nil {
			return MemoryUsage{}, err
		}
	}
	return usage, nil
}

// readCounter reads a single-value interface file such as memory.current.
func readCounter(file string) (int64, error) {
	content, err := os.ReadFile(file) // #nosec G304 -- a leaf interface file under the configured cgroup tree
	if err != nil {
		return 0, &ErrCgroup{Path: file, Op: "read", Cause: err}
	}
	text := strings.TrimSpace(string(content))
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, &ErrCgroupFormat{Path: file, Line: text}
	}
	return value, nil
}

// keyedCounters is a flat-keyed interface file ("key value" per line), such
// as cgroup.events or memory.events.
type keyedCounters map[string]int64

// readKeyed parses a flat-keyed interface file.
func readKeyed(file string) (keyedCounters, error) {
	content, err := os.ReadFile(file) // #nosec G304 -- a leaf interface file under the configured cgroup tree
	if err != nil {
		return nil, &ErrCgroup{Path: file, Op: "read", Cause: err}
	}
	counters := keyedCounters{}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, &ErrCgroupFormat{Path: file, Line: line}
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return nil, &ErrCgroupFormat{Path: file, Line: line}
		}
		counters[fields[0]] = value
	}
	return counters, nil
}

// value is one key's count; a key the file does not carry is a format
// error, because every kernel that has the file writes the keys read here.
func (c keyedCounters) value(file, key string) (int64, error) {
	value, ok := c[key]
	if !ok {
		return 0, &ErrCgroupFormat{Path: file, Line: key + " missing"}
	}
	return value, nil
}
