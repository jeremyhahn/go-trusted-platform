//go:build integration

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

package sdn

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	// ovsCheckTimeout is the timeout for checking OVS availability
	ovsCheckTimeout = 2 * time.Second

	// ovsdbSocketPath is where the devcontainer's ovsdb-server listens
	// (build/docker/devcontainer/run-integration-tests.sh, start_ovs).
	ovsdbSocketPath = "/var/run/openvswitch/db.sock"

	// devcontainerRemedy tells the reader how to get every prerequisite
	// checked in this file: the devcontainer installs and starts them.
	devcontainerRemedy = "run the suite through `make integration-test-sdn`, whose devcontainer " +
		"runs as root and starts Open vSwitch (build/docker/devcontainer/run-integration-tests.sh, start_ovs)"
)

// PrerequisiteError reports that a prerequisite the devcontainer provides is
// missing. The suite fails on it instead of skipping: a skipped integration
// test is a green that proved nothing.
type PrerequisiteError struct {
	// Prerequisite names what is missing.
	Prerequisite string

	// Remedy says how to provide it.
	Remedy string

	// Err is the underlying cause, when there is one.
	Err error
}

// Error implements the error interface.
func (e *PrerequisiteError) Error() string {
	msg := "SDN integration prerequisite missing: " + e.Prerequisite
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg + "; " + e.Remedy
}

// Unwrap returns the underlying cause.
func (e *PrerequisiteError) Unwrap() error {
	return e.Err
}

// missing builds a PrerequisiteError with the devcontainer remedy.
func missing(prerequisite string, err error) error {
	return &PrerequisiteError{Prerequisite: prerequisite, Remedy: devcontainerRemedy, Err: err}
}

// checkRoot reports whether the test runs with root privileges, which OVS
// and network interface tests need.
func checkRoot() error {
	if os.Geteuid() != 0 {
		return missing("root privileges", nil)
	}
	return nil
}

// checkCommand reports whether the named command is in PATH.
func checkCommand(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return missing("the "+name+" command", err)
	}
	return nil
}

// checkOVS reports whether ovs-vsctl exists and the OVS daemons answer it.
func checkOVS() error {
	if err := checkCommand("ovs-vsctl"); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), ovsCheckTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ovs-vsctl", "list-br").CombinedOutput()
	if err != nil {
		return missing("a running Open vSwitch (ovs-vsctl list-br: "+strings.TrimSpace(string(out))+")", err)
	}
	return nil
}

// checkOVSDB reports whether the OVSDB socket exists and OVS is running.
func checkOVSDB() error {
	if _, err := os.Stat(ovsdbSocketPath); err != nil {
		return missing("the OVSDB socket "+ovsdbSocketPath, err)
	}
	return checkOVS()
}

// checkOVSDBAt reports whether the OVSDB server answers at address. A
// "tcp:host:port" address is dialled with ovs-vsctl; any other address is
// taken to be the local socket.
func checkOVSDBAt(address string) error {
	if !strings.HasPrefix(address, "tcp:") {
		return checkOVSDB()
	}

	ctx, cancel := context.WithTimeout(context.Background(), ovsCheckTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ovs-vsctl", "--db="+address, "list-br").CombinedOutput()
	if err != nil {
		return missing("OVSDB at "+address+" (ovs-vsctl: "+strings.TrimSpace(string(out))+")", err)
	}
	return nil
}

// requirePrerequisite fails the test when a prerequisite check failed.
func requirePrerequisite(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// requireRoot fails the test unless it runs with root privileges.
func requireRoot(t *testing.T) {
	t.Helper()
	requirePrerequisite(t, checkRoot())
}

// requireCommand fails the test unless the named command is in PATH.
func requireCommand(t *testing.T, name string) {
	t.Helper()
	requirePrerequisite(t, checkCommand(name))
}

// requireOVS fails the test unless Open vSwitch is running.
func requireOVS(t *testing.T) {
	t.Helper()
	requirePrerequisite(t, checkOVS())
}

// requireOVSDB fails the test unless the OVSDB socket exists and OVS runs.
func requireOVSDB(t *testing.T) {
	t.Helper()
	requirePrerequisite(t, checkOVSDB())
}

// requireOVSDBAt fails the test unless the OVSDB server answers at address.
func requireOVSDBAt(t *testing.T, address string) {
	t.Helper()
	requirePrerequisite(t, checkOVSDBAt(address))
}

// requireOVSOfctl fails the test unless ovs-ofctl exists and OVS runs; the
// OpenFlow flow manipulation tests need both.
func requireOVSOfctl(t *testing.T) {
	t.Helper()
	requirePrerequisite(t, checkCommand("ovs-ofctl"))
	requireOVS(t)
}

// requireOVSForTest fails the test unless it runs as root with OVS running.
func requireOVSForTest(t *testing.T) {
	t.Helper()
	requireRoot(t)
	requireOVS(t)
}

// requireOVSDBForTest fails the test unless it runs as root with the OVSDB
// socket available.
func requireOVSDBForTest(t *testing.T) {
	t.Helper()
	requireRoot(t)
	requireOVSDB(t)
}
