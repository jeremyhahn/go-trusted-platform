// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package container

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// freePort returns a TCP port with nothing on it, and a UDP port likewise.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// readinessManifest writes the minimum on-disk state NewServer needs.
func readinessManifest(t *testing.T) (manifestPath, kernel, initrd string) {
	t.Helper()
	dir := t.TempDir()
	manifestPath = filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	kernel = filepath.Join(dir, "vmlinuz")
	initrd = filepath.Join(dir, "initramfs")
	for _, p := range []string{kernel, initrd} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return manifestPath, kernel, initrd
}

// TestStart_DeviceScriptNeverBindsWhenAListenerFails is the regression
// for the startup race that made an HTTP-only readiness probe unsound.
//
// The container binds HTTP, TFTP, DHCP and the device-script listener
// concurrently. If the device-script port came up on its own schedule, a
// deploy gate probing it could pass while a TFTP or DHCP bind failure
// was still in flight — Phase 2 reports success and the node then
// PXE-boots into nothing, because TFTP is what serves the firmware.
//
// So the device-script listener binds only after the iPXE server reports
// EVERY listener up, and this asserts the consequence: a container whose
// startup fails never begins answering on that port.
//
// Which listener fails is deliberately not asserted here. Unprivileged,
// DHCP loses first — it binds UDP 67, which needs privilege — so this
// test exercises "some listener could not bind" rather than the TFTP
// squat it occupies a port for. The TFTP-specific path is pinned one
// level down, in TestIPXEServerReady_StaysOpenWhenAListenerCannotBind,
// which runs with DHCP off and asserts the address-in-use error.
func TestStart_DeviceScriptNeverBindsWhenAListenerFails(t *testing.T) {
	manifestPath, kernel, initrd := readinessManifest(t)

	// Occupy the TFTP port so its bind cannot succeed.
	squatter, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy udp: %v", err)
	}
	defer squatter.Close()
	tftpPort := squatter.LocalAddr().(*net.UDPAddr).Port

	devScriptPort := freeTCPPort(t)
	cfg := &ServerConfig{
		Interface:        "lo",
		HTTPPort:         freeTCPPort(t),
		TFTPPort:         tftpPort,
		DeviceScriptPort: devScriptPort,
		ManifestPath:     manifestPath,
		KernelPath:       kernel,
		InitrdPath:       initrd,
		DHCPConfig: DHCPConfig{
			ServerIP:   "127.0.0.1",
			RangeStart: "127.0.0.2",
			RangeEnd:   "127.0.0.3",
			SubnetMask: "255.255.255.0",
		},
	}

	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Start returned nil despite a listener failing to bind — the failure is being masked from the caller")
		}
		if !strings.Contains(err.Error(), "bind") {
			t.Fatalf("Start error = %v; want it to name a bind failure", err)
		}
	case <-ctx.Done():
		t.Fatal("Start neither returned nor failed within the deadline")
	}

	// The device-script port must never have started answering: that is
	// the property the deploy gate relies on.
	conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(devScriptPort)), 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatal("the device-script listener bound even though another listener did not — probing it would report a broken container as ready")
	}
}

// TestIPXEServerReady_ClosesOnlyAfterEveryListenerBinds is the positive
// counterpart, exercised one level down.
//
// It cannot be done through container.Server here: that always enables
// DHCP, which binds UDP port 67 and so cannot succeed unprivileged —
// itself the mechanism working, just not something a unit test can
// satisfy. So this drives ipxe.Server directly with DHCP off,
// and asserts Ready closes once HTTP and TFTP are both up. Without that,
// the negative test above would pass against a Ready that never closes
// at all.
func TestIPXEServerReady_ClosesOnlyAfterEveryListenerBinds(t *testing.T) {
	cfg := &ipxe.ServerConfig{
		HTTPPort:    freeTCPPort(t),
		TFTPPort:    freeUDPPort(t),
		EnableDHCP:  false,
		BootEntries: []ipxe.BootEntry{{Name: "probe", Description: "readiness", Kernel: "/dev/null"}},
	}
	srv, err := ipxe.NewServer(cfg, logging.NewLogger(slog.LevelError, io.Discard))
	if err != nil {
		t.Fatalf("ipxe.NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("Ready never closed with every listener able to bind")
	}
}

// TestIPXEServerReady_StaysOpenWhenAListenerCannotBind pins the other
// half: a Ready that closed regardless would make the ordering above
// meaningless.
func TestIPXEServerReady_StaysOpenWhenAListenerCannotBind(t *testing.T) {
	squatter, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy udp: %v", err)
	}
	defer squatter.Close()

	cfg := &ipxe.ServerConfig{
		HTTPPort:    freeTCPPort(t),
		TFTPPort:    squatter.LocalAddr().(*net.UDPAddr).Port,
		EnableDHCP:  false,
		BootEntries: []ipxe.BootEntry{{Name: "probe", Description: "readiness", Kernel: "/dev/null"}},
	}
	srv, err := ipxe.NewServer(cfg, logging.NewLogger(slog.LevelError, io.Discard))
	if err != nil {
		t.Fatalf("ipxe.NewServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start(ctx) }()

	select {
	case <-srv.Ready():
		t.Fatal("Ready closed even though TFTP could not bind")
	case err := <-startErr:
		if err == nil {
			t.Fatal("Start returned nil despite a TFTP bind failure — the failure is masked from the caller")
		}
		// Assert the injected failure is the one under test: without
		// this the test would also pass on a firmware-load error, which
		// happens BEFORE the bind and would prove nothing about
		// bind-before-serve.
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Start error = %v; want the squatted TFTP port's address-already-in-use", err)
		}
	case <-ctx.Done():
		t.Fatal("neither Ready nor Start settled within the deadline")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}
