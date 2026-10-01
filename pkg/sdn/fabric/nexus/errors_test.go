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

package nexus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

func TestErrVLANExists_Error(t *testing.T) {
	err := ErrVLANExists{VLAN: 200, ExistingName: "old", RequestedName: "new"}
	msg := err.Error()
	if !strings.Contains(msg, "200") || !strings.Contains(msg, "old") || !strings.Contains(msg, "new") {
		t.Fatalf("expected VLAN, existing, and requested in error, got %q", msg)
	}
}

func TestErrCommandExec_Error(t *testing.T) {
	cause := errors.New("ssh timeout")
	err := ErrCommandExec{Command: "show vlan", Cause: cause}
	msg := err.Error()
	if !strings.Contains(msg, "show vlan") || !strings.Contains(msg, "ssh timeout") {
		t.Fatalf("expected command and cause in error, got %q", msg)
	}
}

func TestErrCommandExec_ErrorWithOutput(t *testing.T) {
	cause := errors.New("failed")
	err := ErrCommandExec{Command: "show vlan", Output: "% Invalid command", Cause: cause}
	msg := err.Error()
	if !strings.Contains(msg, "% Invalid command") {
		t.Fatalf("expected output in error, got %q", msg)
	}
}

func TestErrCommandExec_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := ErrCommandExec{Command: "test", Cause: cause}
	if !errors.Is(err, cause) {
		t.Fatal("expected Unwrap to return cause")
	}
}

func TestErrParseOutput_Error(t *testing.T) {
	err := ErrParseOutput{Command: "show vlan", Reason: "unexpected format"}
	msg := err.Error()
	if !strings.Contains(msg, "show vlan") || !strings.Contains(msg, "unexpected format") {
		t.Fatalf("expected command and reason in error, got %q", msg)
	}
}

func TestErrNotConnected_Error(t *testing.T) {
	err := ErrNotConnected{}
	if !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected 'not connected' in error, got %q", err.Error())
	}
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Reason: "missing host"}
	if !strings.Contains(err.Error(), "missing host") {
		t.Fatalf("expected reason in error, got %q", err.Error())
	}
}

func TestClose_WithoutConnection(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}
	// Close without ever connecting should not error.
	if err := drv.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}
}

func TestClose_AfterConnect(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{responses: map[string]mockResponse{}}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}
	if err := drv.Close(); err != nil {
		t.Fatalf("Close: %s", err)
	}
}

func TestEnsureLAG_NotConnected(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}
	lag := fabric.LAGConfig{ID: "lag-01", PortChannelID: 10, Members: []fabric.PortRef{{SwitchID: "sw-01", Port: "Eth1/1"}}}
	err = drv.EnsureLAG(context.Background(), lag)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestSetPortAccess_NotConnected(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}
	port := fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/1"}
	err = drv.SetPortAccess(context.Background(), port, 200, 9216)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestExecuteBatch_OutputError(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"interface Eth1/7": {
				stdout: "% Error: permission denied",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	err := drv.DisablePort(ctx, fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/7"})
	if err == nil {
		t.Fatal("expected error for output containing error")
	}
	var cmdErr ErrCommandExec
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected ErrCommandExec, got %T: %s", err, err)
	}
}

func TestPing_ErrorOutput(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show version | head 1": {
				stdout: "% Error: something went wrong",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	err := drv.Ping(ctx)
	if err == nil {
		t.Fatal("expected error for error in ping output")
	}
}

func TestConnect_Idempotent(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{responses: map[string]mockResponse{}}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}
	// Second connect should be a no-op.
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("second Connect: %s", err)
	}
}

// TestConnect_ConfigErrors covers the fail-closed checks before any dial:
// missing key path, missing known-hosts path, an unreadable key, and a key
// that does not parse.
func TestConnect_ConfigErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := testSwitchConfig()
	cfg.SSHKeyPath = ""
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}
	var invalid ErrInvalidConfig
	if err := drv.Connect(ctx); !errors.As(err, &invalid) {
		t.Fatalf("want ErrInvalidConfig for ssh-key-path, got %v", err)
	}

	cfg.SSHKeyPath = filepath.Join(dir, "missing")
	cfg.KnownHostsPath = ""
	drv, _ = NewDriver(cfg, testLogger())
	if err := drv.Connect(ctx); !errors.As(err, &invalid) {
		t.Fatalf("want ErrInvalidConfig for known-hosts-path, got %v", err)
	}

	cfg.KnownHostsPath = filepath.Join(dir, "known_hosts")
	drv, _ = NewDriver(cfg, testLogger())
	var load ErrSSHKeyLoad
	if err := drv.Connect(ctx); !errors.As(err, &load) {
		t.Fatalf("want ErrSSHKeyLoad for a missing key, got %v", err)
	}
	if !strings.Contains(load.Error(), cfg.SSHKeyPath) || errors.Unwrap(load) == nil {
		t.Fatalf("ErrSSHKeyLoad must name the path and wrap the cause: %v", load)
	}

	garbage := filepath.Join(dir, "id_bad")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %s", err)
	}
	cfg.SSHKeyPath = garbage
	drv, _ = NewDriver(cfg, testLogger())
	if err := drv.Connect(ctx); !errors.As(err, &load) {
		t.Fatalf("want ErrSSHKeyLoad for an unparseable key, got %v", err)
	}
	if err := drv.Close(); err != nil {
		t.Fatalf("Close on a never-connected driver: %s", err)
	}
}
