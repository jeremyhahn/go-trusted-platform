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

// readinessManifest writes the minimum on-disk state NewServer needs.
func readinessManifest(t *testing.T) (manifestPath, dataDir string) {
	t.Helper()
	manifestPath = filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte("nodes: []\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return manifestPath, testDataDir(t, x86Set())
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
// The failing listener is the squatted TFTP port, deterministically.
//
// It used to be whichever lost first: DHCP bound the real UDP 67, so
// unprivileged it failed before TFTP was reached, and the test asserted
// only "some listener could not bind". That made its mechanism depend on
// the privilege of whoever ran it — as root, DHCP binds and the TFTP
// squat is what fails, so the same green came from a different path.
// DHCP now takes a free port like every other listener here (#362), so
// the squat is the only failure and the error can be named.
func TestStart_DeviceScriptNeverBindsWhenAListenerFails(t *testing.T) {
	manifestPath, dataDir := readinessManifest(t)

	// Occupy the TFTP port so its bind cannot succeed.
	squatter, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy udp: %v", err)
	}
	defer squatter.Close()
	tftpPort := squatter.LocalAddr().(*net.UDPAddr).Port

	tcpPorts := freeTCPPorts(t, 2)
	devScriptPort := tcpPorts[0]
	cfg := &ServerConfig{
		Interface:        "lo",
		HTTPPort:         tcpPorts[1],
		TFTPPort:         tftpPort,
		DeviceScriptPort: devScriptPort,
		FirmwareDir:      fixtureFirmwareDir(t),
		FirmwareOffline:  true,
		ManifestPath:     manifestPath,
		DataDir:          dataDir,
		MediaDir:         filepath.Join(dataDir, "media"),
		DHCPConfig: DHCPConfig{
			ServerIP:   "127.0.0.1",
			RangeStart: "127.0.0.2",
			RangeEnd:   "127.0.0.3",
			SubnetMask: "255.255.255.0",
			// Never the real 67: it is privileged, globally unique, and
			// owned by the host rather than this test.
			// The squatter still holds the TFTP port, so this one differs.
			Port: freeUDPPorts(t, 1)[0],
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
		// Name the injected failure, not merely "a bind failure": with DHCP
		// on a free port the squatted TFTP port is the only listener that
		// can fail, so a different error means something else broke.
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Start error = %v; want the squatted TFTP port's address-already-in-use", err)
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
// This drives ipxe.Server directly, with DHCP off, and asserts Ready
// closes once HTTP and TFTP are both up. Without it, the negative test
// above would pass against a Ready that never closes at all.
//
// Going one level down is deliberate: the contract under test is
// ipxe.Server's, not the container's. (It used to be forced, too —
// container.Server always bound the real UDP 67 — but #362 made that
// port configurable, so only the first reason still applies.)
func TestIPXEServerReady_ClosesOnlyAfterEveryListenerBinds(t *testing.T) {
	cfg := &ipxe.ServerConfig{
		// Loopback names the server IP outright: auto-detection wants a
		// routable interface, and the hermetic test container has only lo.
		BindHost:        "127.0.0.1",
		HTTPPort:        freeTCPPorts(t, 1)[0],
		TFTPPort:        freeUDPPorts(t, 1)[0],
		EnableDHCP:      false,
		FirmwareDir:     fixtureFirmwareDir(t),
		FirmwareOffline: true,
		BootEntries:     []ipxe.BootEntry{{Name: "probe", Description: "readiness", Kernel: "/dev/null"}},
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
		// Loopback names the server IP outright: auto-detection wants a
		// routable interface, and the hermetic test container has only lo.
		BindHost: "127.0.0.1",
		HTTPPort: freeTCPPorts(t, 1)[0],
		TFTPPort: squatter.LocalAddr().(*net.UDPAddr).Port,
		// Without the fixture the TFTP server fetches firmware from
		// boot.ipxe.org before it binds, and on a runner with no egress
		// that fetch outlives the deadline below — so the test times out
		// instead of asserting anything about the bind (#590, #627).
		FirmwareDir:     fixtureFirmwareDir(t),
		FirmwareOffline: true,
		EnableDHCP:      false,
		BootEntries:     []ipxe.BootEntry{{Name: "probe", Description: "readiness", Kernel: "/dev/null"}},
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

// fixtureFirmwareDir returns a directory holding placeholder iPXE firmware
// so the TFTP server never downloads from boot.ipxe.org inside a unit test
// (#590): a unit test never leaves the process, and the 5 s deadlines in
// this file are for hangs, not for the internet.
func fixtureFirmwareDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"ipxe.efi", "ipxe32.efi", "undionly.kpxe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture "+name), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}
