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

package switchmgmt

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// nxosMode is the CLI mode of one NX-OS exec channel.
type nxosMode int

const (
	nxosExecMode nxosMode = iota
	nxosConfigMode
	nxosInterfaceMode
)

const nxosInvalidOutput = "% Invalid command at '^' marker."

// nxosExecSession is an SSHExecutor fake that models one SSH exec channel
// per Execute, as go-xkms Session.Run opens: every call starts in exec mode,
// so configure-terminal and interface context last only within one command
// line. The line is split on the NX-OS " ; " separator; a configuration
// command outside its mode answers nxosInvalidOutput and stops the line.
type nxosExecSession struct {
	executes   int
	accessVLAN map[string]uint16
	enabled    map[string]bool
}

func newNXOSExecSession() *nxosExecSession {
	return &nxosExecSession{
		accessVLAN: make(map[string]uint16),
		enabled:    make(map[string]bool),
	}
}

func (s *nxosExecSession) Execute(_ context.Context, line string) (string, error) {
	s.executes++
	mode := nxosExecMode
	port := ""
	for _, cmd := range strings.Split(line, " ; ") {
		cmd = strings.TrimSpace(cmd)
		switch {
		case cmd == "configure terminal" && mode == nxosExecMode:
			mode = nxosConfigMode
		case strings.HasPrefix(cmd, "interface ") && mode != nxosExecMode:
			port = strings.TrimPrefix(cmd, "interface ")
			mode = nxosInterfaceMode
		case cmd == "switchport mode access" && mode == nxosInterfaceMode:
		case strings.HasPrefix(cmd, "switchport access vlan ") && mode == nxosInterfaceMode:
			v, err := strconv.ParseUint(strings.TrimPrefix(cmd, "switchport access vlan "), 10, 16)
			if err != nil {
				return nxosInvalidOutput, nil
			}
			s.accessVLAN[port] = uint16(v)
		case cmd == "shutdown" && mode == nxosInterfaceMode:
			s.enabled[port] = false
		case cmd == "no shutdown" && mode == nxosInterfaceMode:
			s.enabled[port] = true
		case cmd == "end" && mode != nxosExecMode:
			mode = nxosExecMode
		default:
			return nxosInvalidOutput, nil
		}
	}
	return "", nil
}

func (s *nxosExecSession) Close() error { return nil }

func TestSSHManager_SetPortVLAN_OneSessionKeepsConfigMode(t *testing.T) {
	sess := newNXOSExecSession()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), sess)

	if err := mgr.SetPortVLAN(context.Background(), "Eth1/3", 100); err != nil {
		t.Fatalf("SetPortVLAN: %v", err)
	}
	if got := sess.accessVLAN["Eth1/3"]; got != 100 {
		t.Fatalf("access vlan of Eth1/3 = %d, want 100", got)
	}
	if sess.executes != 1 {
		t.Fatalf("SetPortVLAN used %d exec channels, want 1", sess.executes)
	}
}

func TestSSHManager_EnablePort_OneSessionKeepsConfigMode(t *testing.T) {
	sess := newNXOSExecSession()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), sess)

	if err := mgr.EnablePort(context.Background(), "Eth1/5"); err != nil {
		t.Fatalf("EnablePort: %v", err)
	}
	if enabled, ok := sess.enabled["Eth1/5"]; !ok || !enabled {
		t.Fatalf("Eth1/5 enabled = %v (set %v), want true", enabled, ok)
	}
	if sess.executes != 1 {
		t.Fatalf("EnablePort used %d exec channels, want 1", sess.executes)
	}
}

func TestSSHManager_DisablePort_OneSessionKeepsConfigMode(t *testing.T) {
	sess := newNXOSExecSession()
	sess.enabled["Eth1/5"] = true
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), sess)

	if err := mgr.DisablePort(context.Background(), "Eth1/5"); err != nil {
		t.Fatalf("DisablePort: %v", err)
	}
	if sess.enabled["Eth1/5"] {
		t.Fatal("Eth1/5 is still enabled, want disabled")
	}
	if sess.executes != 1 {
		t.Fatalf("DisablePort used %d exec channels, want 1", sess.executes)
	}
}
