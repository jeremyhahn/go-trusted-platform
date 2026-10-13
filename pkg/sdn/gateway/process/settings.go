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
	"log/slog"
	"os/user"
	"strconv"
	"time"
)

// DefaultRuntimeDir holds the per-process control sockets.
const DefaultRuntimeDir = "/run/gatewayd"

// DefaultCgroupParent is the cgroup v2 directory the per-process leaves live
// under. It is relative to the cgroup root.
const DefaultCgroupParent = "gatewayd"

// DefaultServiceUser is the account the unprivileged parser processes run
// as. It is created by the package install, not by gatewayd.
const DefaultServiceUser = "gatewayd"

// Settings is the `process:` configuration section: whether gatewayd
// supervises its services in separate processes, and the knobs an operator
// may turn. The privilege classes themselves are not configuration — they
// are the class table in this package, so a deployment cannot quietly widen
// what a parser process may do.
type Settings struct {
	// Enabled turns on the supervised process model. Off means the daemon
	// runs every service in one process, as it did before #557.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// RuntimeDir holds the per-process control sockets.
	RuntimeDir string `yaml:"runtime-dir" json:"runtime_dir" mapstructure:"runtime-dir"`
	// User and Group are the account the parser classes drop to.
	User  string `yaml:"user" json:"user" mapstructure:"user"`
	Group string `yaml:"group" json:"group" mapstructure:"group"`
	// CgroupRoot is the cgroup v2 mount point; empty means the standard one.
	CgroupRoot string `yaml:"cgroup-root" json:"cgroup_root" mapstructure:"cgroup-root"`
	// CgroupParent is the directory holding one leaf per process. Absent
	// means DefaultCgroupParent; set explicitly to "" to run without cgroup
	// placement — the capability separation stays, the resource limits go.
	// It is a pointer so those two cases are distinguishable: an operator
	// who writes `cgroup-parent: ""` means it.
	CgroupParent *string `yaml:"cgroup-parent" json:"cgroup_parent" mapstructure:"cgroup-parent"`
	// ReadyTimeout, StopTimeout, RestartBudget and RestartWindow override
	// the Default* constants.
	ReadyTimeout  time.Duration `yaml:"ready-timeout" json:"ready_timeout" mapstructure:"ready-timeout"`
	StopTimeout   time.Duration `yaml:"stop-timeout" json:"stop_timeout" mapstructure:"stop-timeout"`
	RestartBudget int           `yaml:"restart-budget" json:"restart_budget" mapstructure:"restart-budget"`
	RestartWindow time.Duration `yaml:"restart-window" json:"restart_window" mapstructure:"restart-window"`
}

// ErrUserUnknown reports a configured service account that does not exist on
// the host. The supervisor refuses rather than running a parser as root.
type ErrUserUnknown struct {
	Name  string
	Cause error
}

func (e *ErrUserUnknown) Error() string {
	return "gatewayd supervisor: service account " + strconv.Quote(e.Name) + " does not exist: " + e.Cause.Error()
}

func (e *ErrUserUnknown) Unwrap() error { return e.Cause }

// Config builds the supervisor configuration from the settings, resolving
// the service account and filling defaults. inherited is the part of the
// supervisor's command line every child is started with.
func (s Settings) Config(inherited Inherited, logger *slog.Logger) (Config, error) {
	runtimeDir := s.RuntimeDir
	if runtimeDir == "" {
		runtimeDir = DefaultRuntimeDir
	}
	account := s.User
	if account == "" {
		account = DefaultServiceUser
	}
	uid, gid, err := lookupAccount(account, s.Group)
	if err != nil {
		return Config{}, err
	}
	cgroupParent := DefaultCgroupParent
	if s.CgroupParent != nil {
		cgroupParent = *s.CgroupParent
	}
	return Config{
		RuntimeDir: runtimeDir,
		Inherited:  inherited,
		UID:        uid,
		GID:        gid,
		// The control sockets are group-owned by the service account so an
		// unprivileged parser can reach the datapath process's socket.
		SocketGID:     int(gid),
		Cgroups:       &CgroupManager{Root: s.CgroupRoot, Parent: cgroupParent},
		ReadyTimeout:  s.ReadyTimeout,
		StopTimeout:   s.StopTimeout,
		RestartBudget: s.RestartBudget,
		RestartWindow: s.RestartWindow,
		Logger:        logger,
	}, nil
}

// lookupAccount resolves the service account's uid and gid. An explicit
// group overrides the account's primary group.
func lookupAccount(account, group string) (uint32, uint32, error) {
	found, err := user.Lookup(account)
	if err != nil {
		return 0, 0, &ErrUserUnknown{Name: account, Cause: err}
	}
	uid, err := strconv.ParseUint(found.Uid, 10, 32)
	if err != nil {
		return 0, 0, &ErrUserUnknown{Name: account, Cause: err}
	}
	gidText := found.Gid
	if group != "" {
		foundGroup, err := user.LookupGroup(group)
		if err != nil {
			return 0, 0, &ErrUserUnknown{Name: group, Cause: err}
		}
		gidText = foundGroup.Gid
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		return 0, 0, &ErrUserUnknown{Name: account, Cause: err}
	}
	return uint32(uid), uint32(gid), nil
}
