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

package iso

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// The tests in this file swap the package-level host seams, so none of
// them calls t.Parallel.

// fakeNetwork is the client-server test's isolated network, kept in memory.
type fakeNetwork struct {
	testenv.IsolatedNetwork
	cfg      *testenv.NetworkConfig
	setupErr error
	rulesErr error
	setups   int
	rules    int
	cleanups int
	phases   map[string]testenv.NetworkPhase
}

func (n *fakeNetwork) Setup() error                   { n.setups++; return n.setupErr }
func (n *fakeNetwork) EnsureRules() error             { n.rules++; return n.rulesErr }
func (n *fakeNetwork) Cleanup() error                 { n.cleanups++; return nil }
func (n *fakeNetwork) Config() *testenv.NetworkConfig { return n.cfg }
func (n *fakeNetwork) ServerTapName() string          { return n.cfg.ServerTapName }
func (n *fakeNetwork) ClientTapName() string          { return n.cfg.ClientTapName }
func (n *fakeNetwork) SetPhase(port string, phase testenv.NetworkPhase) error {
	n.phases[port] = phase
	return nil
}

// csFake swaps the client-server network seams and the shared server state.
type csFake struct {
	network      *fakeNetwork
	rootErr      error
	ovsAvailable bool
	exists       bool
	ovsErr       error
	ovsOpts      []*testenv.OVSNetworkOptions
	stale        int
}

func withCSFake(t *testing.T) *csFake {
	t.Helper()
	f := &csFake{ovsAvailable: true}
	root, ovs, exists, stale, linux, ovsNet := csCheckRoot, csOVSAvailable, csNetworkExists, csCleanupStale, csNewLinuxNetwork, csNewOVSNetwork
	poll, boot, state, bundle := csReadyPollInterval, csMinBootTime, csServerState, csServerCABundlePath
	t.Cleanup(func() {
		csCheckRoot, csOVSAvailable, csNetworkExists, csCleanupStale, csNewLinuxNetwork, csNewOVSNetwork = root, ovs, exists, stale, linux, ovsNet
		csReadyPollInterval, csMinBootTime, csServerState, csServerCABundlePath = poll, boot, state, bundle
	})
	csCheckRoot = func() error { return f.rootErr }
	csOVSAvailable = func() bool { return f.ovsAvailable }
	csNetworkExists = func(*testenv.NetworkConfig) bool { return f.exists }
	csCleanupStale = func(*testenv.NetworkConfig) { f.stale++ }
	csNewLinuxNetwork = func(cfg *testenv.NetworkConfig) testenv.IsolatedNetwork {
		f.network = &fakeNetwork{cfg: cfg, phases: map[string]testenv.NetworkPhase{}}
		return f.network
	}
	csNewOVSNetwork = func(cfg *testenv.NetworkConfig, opts *testenv.OVSNetworkOptions) (testenv.IsolatedNetwork, error) {
		f.ovsOpts = append(f.ovsOpts, opts)
		if f.ovsErr != nil {
			return nil, f.ovsErr
		}
		f.network = &fakeNetwork{cfg: cfg, phases: map[string]testenv.NetworkPhase{}}
		return f.network, nil
	}
	csReadyPollInterval = time.Millisecond
	csMinBootTime = 0
	csServerState = nil
	csServerCABundlePath = ""
	return f
}

func csFlagsFor(t *testing.T) *clientServerFlags {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), mode))
		return path
	}
	return &clientServerFlags{
		serverDisk:       filepath.Join(dir, "server.qcow2"),
		clientDisk:       filepath.Join(dir, "client.qcow2"),
		serverWorkDir:    filepath.Join(dir, "server"),
		clientWorkDir:    filepath.Join(dir, "client"),
		diskSize:         "8G",
		memory:           1024,
		cpus:             1,
		serverConfigPath: write("server.yaml", "debug: false\nnetwork: {}\n", 0o600),
		clientConfigPath: write("client.yaml", "debug: false\nnetwork: {}\n", 0o600),
		platformdBinary:  write("platformd", "#!/bin/true\n", 0o700),
		webUIPath:        write("public_html.tar.gz", "ui", 0o600),
		serverHostPort:   18443,
		dnsHostPort:      18053,
		serverTimeout:    1,
	}
}

// withInstallingVMs fakes QEMU so every guest leaves an installed disk.
func withInstallingVMs(t *testing.T) *vmFake {
	t.Helper()
	vms := withVMFake(t)
	vms.onWait = func(cfg *qemu.Config) { writeInstalledDisk(t, cfg.DiskPath) }
	return vms
}

func TestHostSeams_ClientServerServerOnly(t *testing.T) {
	withFirmware(t)
	net := withCSFake(t)
	pipe := withPipelineFake(t)
	cmds := withCommandFake(t)
	vms := withInstallingVMs(t)
	flags := csFlagsFor(t)
	flags.serverOnly = true

	require.NoError(t, runClientServerTest(getTestFlags(), flags))

	assert.Equal(t, 1, net.stale, "stale resources are cleared before the network is built")
	assert.Equal(t, 1, net.network.setups)
	assert.Equal(t, 1, net.network.cleanups, "the server-only run owns the network")
	require.Len(t, pipe.builds, 1)
	assert.Equal(t, filepath.Join(flags.serverWorkDir, "server.iso"), pipe.builds[0].OutputISO)
	assert.Equal(t, [][]string{{"qemu-img", "create", "-f", "qcow2", flags.serverDisk, "8G"}}, cmds.argv)
	assert.Equal(t, []string{string(qemu.BootModeInstall), string(qemu.BootModeBoot)}, vms.modes)
	assert.Equal(t, []string{net.network.cfg.ServerTapName}, vms.tapStops)
	for _, cfg := range vms.configs {
		assert.Equal(t, net.network.cfg.ServerTapName, cfg.TapDevice)
		assert.False(t, cfg.SerialConsole, "without a terminal the serial console goes to a file")
	}
	_, err := os.Stat(filepath.Join(flags.serverWorkDir, "platform.yaml"))
	assert.NoError(t, err, "the server's platform config is written")
}

func TestHostSeams_ClientServerOVSPhases(t *testing.T) {
	withFirmware(t)
	net := withCSFake(t)
	withPipelineFake(t)
	withCommandFake(t)
	withInstallingVMs(t)
	flags := csFlagsFor(t)
	flags.serverOnly = true
	flags.skipInstall = true
	flags.useOVS = true
	flags.dynamicNetwork = true
	require.NoError(t, os.WriteFile(flags.serverDisk, []byte("disk"), 0o600))

	require.NoError(t, runClientServerTest(getTestFlags(), flags))

	require.Len(t, net.ovsOpts, 1)
	assert.NotNil(t, net.ovsOpts[0], "dynamic networks carry phase options")
	assert.Equal(t, map[string]testenv.NetworkPhase{
		net.network.cfg.ServerTapName: testenv.NetworkPhaseAdmitted,
		net.network.cfg.ClientTapName: testenv.NetworkPhaseProvisioning,
	}, net.network.phases)
}

func TestHostSeams_ClientServerClientOnly(t *testing.T) {
	withFirmware(t)
	net := withCSFake(t)
	net.exists = true
	pipe := withPipelineFake(t)
	withCommandFake(t)
	vms := withInstallingVMs(t)
	flags := csFlagsFor(t)
	flags.clientOnly = true
	bundle := filepath.Join(t.TempDir(), "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundle, []byte("ca"), 0o600))
	csServerCABundlePath = bundle

	require.NoError(t, runClientServerTest(getTestFlags(), flags))

	assert.Equal(t, 1, net.network.rules, "a reused network has its NAT rules re-applied")
	assert.Zero(t, net.network.setups)
	assert.Zero(t, net.network.cleanups, "the server owns the network")
	assert.Zero(t, net.stale)
	require.Len(t, pipe.builds, 1)
	assert.Equal(t, filepath.Join(flags.clientWorkDir, "client.iso"), pipe.builds[0].OutputISO)
	assert.Equal(t, []string{string(qemu.BootModeInstall), string(qemu.BootModeBoot)}, vms.modes)
	assert.Equal(t, []string{net.network.cfg.ClientTapName}, vms.tapStops)
}

func TestHostSeams_ClientServerBackgroundServer(t *testing.T) {
	t.Run("server never answers", func(t *testing.T) {
		withFirmware(t)
		withCSFake(t)
		withPipelineFake(t)
		cmds := withCommandFake(t)
		cmds.errs["ping"] = errHost
		vms := withInstallingVMs(t)
		vms.running = true
		flags := csFlagsFor(t)
		flags.skipInstall = true
		flags.serverTimeout = 0

		err := runClientServerTest(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "server VM failed", wrapped.Msg)
		var inner *WrappedError
		require.ErrorAs(t, wrapped.Err, &inner)
		assert.Equal(t, "server did not become ready", inner.Msg)
		assert.Equal(t, 1, vms.stops, "the background server is stopped")
		assert.Equal(t, 1, vms.tpmStops)
		assert.Nil(t, csServerState)
	})

	t.Run("CA bundle cannot be fetched", func(t *testing.T) {
		withFirmware(t)
		withCSFake(t)
		withPipelineFake(t)
		withCommandFake(t)
		vms := withInstallingVMs(t)
		flags := csFlagsFor(t)
		flags.skipInstall = true
		flags.bootstrapStrategy = "spki"
		flags.bootstrapSPKIPin = "00"

		err := runClientServerTest(getTestFlags(), flags)
		var fetch ErrCABundleFetch
		require.ErrorAs(t, err, &fetch)
		assert.Contains(t, err.Error(), "failed to fetch CA bundle from server")
		assert.Equal(t, []string{string(qemu.BootModeBoot)}, vms.modes)
		assert.Zero(t, vms.stops, "a VM that is no longer running is not stopped again")
		assert.Equal(t, 1, vms.tpmStops)
		assert.Nil(t, csServerState)
	})

	t.Run("client-only waits for the server first", func(t *testing.T) {
		withFirmware(t)
		net := withCSFake(t)
		net.exists = true
		withPipelineFake(t)
		withCommandFake(t)
		withInstallingVMs(t)
		flags := csFlagsFor(t)
		flags.clientOnly = true
		flags.bootstrapStrategy = "spki"
		flags.bootstrapSPKIPin = "00"

		err := runClientServerTest(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "client VM failed", wrapped.Msg)
		var fetch ErrCABundleFetch
		assert.ErrorAs(t, err, &fetch)
	})
}

func TestHostSeams_ClientServerRejects(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *csFake, flags *clientServerFlags)
		msg   string
	}{
		{"user network needs server-only", func(_ *csFake, fl *clientServerFlags) { fl.userNetwork = true }, "--user-network only supports --server-only mode (single VM testing)"},
		{"OVS and user network", func(_ *csFake, fl *clientServerFlags) {
			fl.userNetwork, fl.serverOnly, fl.useOVS = true, true, true
		}, "--use-ovs and --user-network are mutually exclusive"},
		{"OVS missing", func(f *csFake, fl *clientServerFlags) { fl.useOVS = true; f.ovsAvailable = false },
			"OVS is not available (check if openvswitch is installed and running)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := withCSFake(t)
			flags := csFlagsFor(t)
			tt.setup(f, flags)
			err := runClientServerTest(getTestFlags(), flags)
			var msg *MessageError
			require.ErrorAs(t, err, &msg)
			assert.Equal(t, tt.msg, msg.Msg)
			assert.Nil(t, f.network, "nothing is set up")
		})
	}

	t.Run("not root", func(t *testing.T) {
		f := withCSFake(t)
		f.rootErr = errHost
		err := runClientServerTest(getTestFlags(), csFlagsFor(t))
		assert.ErrorIs(t, err, errHost)
	})

	wrapped := []struct {
		name  string
		setup func(t *testing.T, f *csFake, flags *clientServerFlags)
		msg   string
	}{
		{"OVS network cannot be created", func(_ *testing.T, f *csFake, fl *clientServerFlags) {
			fl.useOVS = true
			f.ovsErr = errHost
		}, "failed to create OVS network"},
		{"dynamic OVS network cannot be created", func(_ *testing.T, f *csFake, fl *clientServerFlags) {
			fl.useOVS, fl.dynamicNetwork = true, true
			f.ovsErr = errHost
		}, "failed to create OVS network"},
		{"reused OVS network cannot be created", func(_ *testing.T, f *csFake, fl *clientServerFlags) {
			fl.useOVS, fl.clientOnly = true, true
			f.exists = true
			f.ovsErr = errHost
		}, "failed to create OVS network"},
		{"server profile missing", func(t *testing.T, _ *csFake, fl *clientServerFlags) {
			fl.serverProfile = filepath.Join(t.TempDir(), "absent.yaml")
		}, "failed to load server profile"},
		{"client profile missing", func(t *testing.T, _ *csFake, fl *clientServerFlags) {
			fl.clientProfile = filepath.Join(t.TempDir(), "absent.yaml")
		}, "failed to load client profile"},
	}
	for _, tt := range wrapped {
		t.Run(tt.name, func(t *testing.T) {
			f := withCSFake(t)
			flags := csFlagsFor(t)
			tt.setup(t, f, flags)
			err := runClientServerTest(getTestFlags(), flags)
			var w *WrappedError
			require.ErrorAs(t, err, &w)
			assert.Equal(t, tt.msg, w.Msg)
		})
	}
}

func TestHostSeams_ClientServerNetworkSetupFails(t *testing.T) {
	tests := []struct {
		name  string
		flags func(*clientServerFlags)
		msg   string
	}{
		{"bridge", func(*clientServerFlags) {}, "failed to setup isolated network"},
		{"OVS", func(fl *clientServerFlags) { fl.useOVS = true }, "failed to setup OVS isolated network"},
		{"dynamic OVS", func(fl *clientServerFlags) { fl.useOVS, fl.dynamicNetwork = true, true }, "failed to setup OVS isolated network"},
		{"reused network rules", func(fl *clientServerFlags) { fl.clientOnly = true }, "failed to ensure network rules"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := withCSFake(t)
			f.exists = true
			flags := csFlagsFor(t)
			tt.flags(flags)
			newLinux, newOVS := csNewLinuxNetwork, csNewOVSNetwork
			csNewLinuxNetwork = func(cfg *testenv.NetworkConfig) testenv.IsolatedNetwork {
				n := newLinux(cfg).(*fakeNetwork)
				n.setupErr, n.rulesErr = errHost, errHost
				return n
			}
			csNewOVSNetwork = func(cfg *testenv.NetworkConfig, opts *testenv.OVSNetworkOptions) (testenv.IsolatedNetwork, error) {
				n, err := newOVS(cfg, opts)
				n.(*fakeNetwork).setupErr = errHost
				return n, err
			}
			if !flags.clientOnly {
				f.exists = false
			}
			err := runClientServerTest(getTestFlags(), flags)
			var w *WrappedError
			require.ErrorAs(t, err, &w)
			assert.Equal(t, tt.msg, w.Msg)
			assert.ErrorIs(t, err, errHost)
		})
	}
}

func TestHostSeams_ClientServerVMFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, flags *clientServerFlags, cmds *commandFake, vms *vmFake)
		msg   string
	}{
		{"server disk", func(_ *testing.T, _ *clientServerFlags, cmds *commandFake, _ *vmFake) {
			cmds.errs["qemu-img"] = errHost
		}, "failed to create server disk"},
		{"server TPM", func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.tpmErr = errHost
		}, "failed to setup server TPM"},
		{"server install", func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.startErr = errHost
		}, "server installation failed"},
		{"server ISO", func(t *testing.T, flags *clientServerFlags, _ *commandFake, _ *vmFake) {
			flags.webUIPath = filepath.Join(t.TempDir(), "absent")
		}, "failed to build server ISO"},
		{"server config", func(t *testing.T, flags *clientServerFlags, _ *commandFake, _ *vmFake) {
			flags.serverConfigPath = filepath.Join(t.TempDir(), "absent.yaml")
		}, "failed to read server platform config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFirmware(t)
			withCSFake(t)
			withPipelineFake(t)
			cmds := withCommandFake(t)
			vms := withInstallingVMs(t)
			flags := csFlagsFor(t)
			flags.serverOnly = true
			tt.setup(t, flags, cmds, vms)
			err := runClientServerTest(getTestFlags(), flags)
			var outer *WrappedError
			require.ErrorAs(t, err, &outer)
			assert.Equal(t, "server VM failed", outer.Msg)
			var inner *WrappedError
			require.ErrorAs(t, outer.Err, &inner)
			assert.Equal(t, tt.msg, inner.Msg)
		})
	}

	clientTests := []struct {
		name  string
		setup func(t *testing.T, flags *clientServerFlags, cmds *commandFake, vms *vmFake)
		msg   string
	}{
		{"client disk", func(_ *testing.T, _ *clientServerFlags, cmds *commandFake, _ *vmFake) {
			cmds.errs["qemu-img"] = errHost
		}, "failed to create client disk"},
		{"client TPM", func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.tpmErr = errHost
		}, "failed to setup client TPM"},
		{"client install", func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.startErr = errHost
		}, "client installation failed"},
		{"client boot", func(_ *testing.T, flags *clientServerFlags, _ *commandFake, vms *vmFake) {
			flags.skipInstall = true
			require.NoError(t, os.WriteFile(flags.clientDisk, []byte("disk"), 0o600))
			vms.startErr = errHost
		}, "client boot failed"},
		{"client config", func(t *testing.T, flags *clientServerFlags, _ *commandFake, _ *vmFake) {
			flags.clientConfigPath = filepath.Join(t.TempDir(), "absent.yaml")
		}, "failed to read client platform config"},
	}
	for _, tt := range clientTests {
		t.Run(tt.name, func(t *testing.T) {
			withFirmware(t)
			f := withCSFake(t)
			f.exists = true
			withPipelineFake(t)
			cmds := withCommandFake(t)
			vms := withInstallingVMs(t)
			flags := csFlagsFor(t)
			flags.clientOnly = true
			bundle := filepath.Join(t.TempDir(), "ca-bundle.pem")
			require.NoError(t, os.WriteFile(bundle, []byte("ca"), 0o600))
			csServerCABundlePath = bundle
			tt.setup(t, flags, cmds, vms)
			err := runClientServerTest(getTestFlags(), flags)
			var outer *WrappedError
			require.ErrorAs(t, err, &outer)
			assert.Equal(t, "client VM failed", outer.Msg)
			var inner *WrappedError
			require.ErrorAs(t, outer.Err, &inner)
			assert.Equal(t, tt.msg, inner.Msg)
		})
	}
}

func TestHostSeams_ClientServerUserNetwork(t *testing.T) {
	userFlags := func(t *testing.T) *clientServerFlags {
		flags := csFlagsFor(t)
		flags.userNetwork = true
		flags.serverOnly = true
		flags.serverTimeout = 0
		return flags
	}

	t.Run("platformd never answers", func(t *testing.T) {
		withFirmware(t)
		f := withCSFake(t)
		f.rootErr = errHost // user-mode networking never needs root
		pipe := withPipelineFake(t)
		cmds := withCommandFake(t)
		cmds.errs["nc"] = errHost
		vms := withInstallingVMs(t)
		flags := userFlags(t)

		err := runClientServerTest(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "server did not become ready", wrapped.Msg)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Contains(t, msg.Msg, "localhost:18443 not responding")

		require.Len(t, pipe.builds, 1)
		assert.Equal(t, []string{string(qemu.BootModeInstall), string(qemu.BootModeBoot)}, vms.modes)
		assert.Equal(t, 1, vms.stops, "the server VM is stopped when it never becomes ready")
		assert.Equal(t, 1, vms.tpmStops, "the boot TPM is stopped through the seam; the install TPM stops itself")
		assert.Nil(t, f.network, "user-mode networking builds no bridge")
		for _, cfg := range vms.configs {
			assert.Empty(t, cfg.TapDevice)
		}
	})

	t.Run("host ports already in use", func(t *testing.T) {
		withFirmware(t)
		withCSFake(t)
		withPipelineFake(t)
		withCommandFake(t)
		vms := withInstallingVMs(t)
		flags := userFlags(t)
		flags.skipInstall = true

		err := runClientServerTest(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "pre-flight check failed", wrapped.Msg)
		assert.Empty(t, vms.modes, "no VM starts while the ports are taken")
	})

	t.Run("server VM does not start", func(t *testing.T) {
		withFirmware(t)
		withCSFake(t)
		withPipelineFake(t)
		cmds := withCommandFake(t)
		cmds.errs["nc"] = errHost
		vms := withInstallingVMs(t)
		vms.startErr = errHost
		flags := userFlags(t)
		flags.skipInstall = true

		err := runClientServerTest(getTestFlags(), flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to start server VM", wrapped.Msg)
		assert.Equal(t, 1, vms.tpmStops)
	})

	t.Run("server ISO cannot be built", func(t *testing.T) {
		withFirmware(t)
		withCSFake(t)
		pipe := withPipelineFake(t)
		pipe.buildErr = errHost
		withCommandFake(t)
		withInstallingVMs(t)

		err := runClientServerTest(getTestFlags(), userFlags(t))
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to build server ISO", wrapped.Msg)
		assert.ErrorIs(t, err, errHost)
	})
}

func TestHostSeams_WaitForCSServerReady(t *testing.T) {
	logger := createTestLogger(false)
	ctx := context.Background()

	t.Run("ready after a reboot", func(t *testing.T) {
		withCSFake(t)
		cmds := withCommandFake(t)
		pings := 0
		cmds.decide = func(args []string) error {
			switch args[0] {
			case "ping":
				pings++
				if pings >= 2 && pings <= 4 {
					return errHost // the firstboot reboot
				}
				return nil
			case "nc":
				if pings < 5 {
					return errHost
				}
			}
			return nil
		}
		require.NoError(t, waitForCSServerReady(ctx, logger, "10.0.0.2", time.Minute))
		assert.Equal(t, 5, pings)
		assert.Contains(t, cmds.argv, []string{"nc", "-z", "-w", "2", "10.0.0.2", "8443"})
	})

	tests := []struct {
		name   string
		decide func(args []string) error
		want   string
	}{
		{"never reachable", func([]string) error { return errHost }, "did not become reachable via ping"},
		{"DNS never opens", func(args []string) error {
			if args[0] == "nc" {
				return errHost
			}
			return nil
		}, "platformd DNS service did not become ready"},
		{"HTTPS never opens", func(args []string) error {
			if args[len(args)-1] == "8443" {
				return errHost
			}
			return nil
		}, "platformd HTTPS service did not become ready"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCSFake(t)
			cmds := withCommandFake(t)
			cmds.decide = tt.decide
			err := waitForCSServerReady(ctx, logger, "10.0.0.2", 5*time.Millisecond)
			var msg *MessageError
			require.ErrorAs(t, err, &msg)
			assert.Contains(t, msg.Msg, tt.want)
		})
	}

	t.Run("cancelled", func(t *testing.T) {
		withCSFake(t)
		withCommandFake(t)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		assert.ErrorIs(t, waitForCSServerReady(cancelled, logger, "10.0.0.2", time.Minute), context.Canceled)
	})
}

func TestHostSeams_CheckCSPortsAvailable(t *testing.T) {
	logger := createTestLogger(false)
	flags := &clientServerFlags{serverHostPort: 18443, dnsHostPort: 18053}

	t.Run("all free", func(t *testing.T) {
		cmds := withCommandFake(t)
		cmds.errs["nc"] = errHost
		require.NoError(t, checkCSPortsAvailable(context.Background(), logger, flags))
		assert.Len(t, cmds.argv, 3)
	})

	t.Run("all taken", func(t *testing.T) {
		withCommandFake(t)
		err := checkCSPortsAvailable(context.Background(), logger, flags)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Contains(t, msg.Msg, "localhost:18443 (HTTPS), localhost:18053 (DNS)")
	})
}

func TestHostSeams_StopCSTPM(t *testing.T) {
	logger := createTestLogger(false)
	stopCSTPM(logger, nil)
	tpm := &fakeTPM{}
	stopCSTPM(logger, tpm)
	assert.Equal(t, 1, tpm.stopped)
}

// statusFake answers the platformd status request in memory.
type statusFake struct {
	urls   []string
	tls    []bool
	status int
	body   io.ReadCloser
	err    error
}

func withStatusFake(t *testing.T) *statusFake {
	t.Helper()
	f := &statusFake{status: http.StatusOK}
	orig := csStatusDo
	t.Cleanup(func() { csStatusDo = orig })
	csStatusDo = func(client *http.Client, req *http.Request) (*http.Response, error) {
		f.urls = append(f.urls, req.URL.String())
		f.tls = append(f.tls, client.Transport.(*http.Transport).TLSClientConfig != nil)
		if f.err != nil {
			return nil, f.err
		}
		body := f.body
		if body == nil {
			body = io.NopCloser(strings.NewReader(`{"tpm":{"ready":true}}`))
		}
		return &http.Response{StatusCode: f.status, Body: body}, nil
	}
	return f
}

// failingBody is a response body whose read fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errHost }
func (failingBody) Close() error             { return nil }

func TestHostSeams_VerifyCSPlatformdStatus(t *testing.T) {
	logger := createTestLogger(false)
	flags := &clientServerFlags{serverHostPort: 18443}

	t.Run("healthy", func(t *testing.T) {
		withCSFake(t)
		status := withStatusFake(t)
		require.NoError(t, verifyCSPlatformdStatus(context.Background(), logger, flags))
		assert.Equal(t, []string{"https://127.0.0.1:18443/api/v1/status"}, status.urls)
		assert.Equal(t, []bool{false}, status.tls, "without a CA bundle the system roots are used")
	})

	t.Run("CA bundle that holds no certificate", func(t *testing.T) {
		withCSFake(t)
		status := withStatusFake(t)
		status.body = io.NopCloser(strings.NewReader("{}"))
		csServerCABundlePath = filepath.Join(t.TempDir(), "ca-bundle.pem")
		require.NoError(t, os.WriteFile(csServerCABundlePath, []byte("not a certificate"), 0o600))
		require.NoError(t, verifyCSPlatformdStatus(context.Background(), logger, flags))
		assert.Equal(t, []bool{false}, status.tls)
	})

	t.Run("connection refused", func(t *testing.T) {
		withCSFake(t)
		withStatusFake(t).err = errHost
		err := verifyCSPlatformdStatus(context.Background(), logger, flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to connect", wrapped.Msg)
		assert.ErrorIs(t, err, errHost)
	})

	t.Run("unhealthy", func(t *testing.T) {
		withCSFake(t)
		withStatusFake(t).status = http.StatusServiceUnavailable
		err := verifyCSPlatformdStatus(context.Background(), logger, flags)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "unexpected status code: 503", msg.Msg)
	})

	t.Run("body cannot be read", func(t *testing.T) {
		withCSFake(t)
		withStatusFake(t).body = failingBody{}
		err := verifyCSPlatformdStatus(context.Background(), logger, flags)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to read response", wrapped.Msg)
		assert.ErrorIs(t, err, errHost)
	})
}

func TestHostSeams_WaitForCSServerReadyUserNetwork(t *testing.T) {
	logger := createTestLogger(false)
	flags := &clientServerFlags{serverHostPort: 18443}

	t.Run("ready once the port opens and the status answers", func(t *testing.T) {
		withCSFake(t)
		cmds := withCommandFake(t)
		ncs := 0
		cmds.decide = func([]string) error {
			ncs++
			if ncs < 2 {
				return errHost
			}
			return nil
		}
		status := withStatusFake(t)
		require.NoError(t, waitForCSServerReadyUserNetwork(context.Background(), logger, flags, time.Minute))
		assert.Equal(t, 2, ncs)
		assert.Len(t, status.urls, 1)
	})

	t.Run("status never verifies", func(t *testing.T) {
		withCSFake(t)
		withCommandFake(t)
		withStatusFake(t).status = http.StatusInternalServerError
		err := waitForCSServerReadyUserNetwork(context.Background(), logger, flags, 5*time.Millisecond)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Contains(t, msg.Msg, "platformd status verification failed within 5ms")
	})

	t.Run("cancelled", func(t *testing.T) {
		withCSFake(t)
		withCommandFake(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := waitForCSServerReadyUserNetwork(ctx, logger, flags, time.Minute)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestHostSeams_ClientServerUserNetworkProvisions(t *testing.T) {
	withFirmware(t)
	withCSFake(t)
	withPipelineFake(t)
	cmds := withCommandFake(t)
	ncs := 0
	cmds.decide = func(args []string) error {
		if args[0] != "nc" {
			return nil
		}
		ncs++
		if ncs <= 3 {
			return errHost // the pre-flight check finds the host ports free
		}
		return nil
	}
	status := withStatusFake(t)
	vms := withInstallingVMs(t)
	flags := csFlagsFor(t)
	flags.userNetwork, flags.serverOnly = true, true

	require.NoError(t, runClientServerTest(getTestFlags(), flags))

	assert.Len(t, status.urls, 1)
	assert.Equal(t, []string{string(qemu.BootModeInstall), string(qemu.BootModeBoot)}, vms.modes)
	assert.Equal(t, 1, vms.stops, "the provisioned server is stopped")
	assert.Equal(t, 1, vms.tpmStops)
	require.NotEmpty(t, vms.configs)
	last := vms.configs[len(vms.configs)-1]
	assert.Equal(t, filepath.Join(flags.serverWorkDir, "server-boot-serial.log"), last.SerialLogFile)
}

// TestHostSeams_ClientServerLegFailures drives each VM leg into the
// failures its host calls can return.
func TestHostSeams_ClientServerLegFailures(t *testing.T) {
	type leg int
	const (
		serverOnly leg = iota
		background
		clientOnly
		userNetwork
	)
	underFile := func(t *testing.T) string {
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		return filepath.Join(file, "work")
	}
	installed := func(t *testing.T, disk string) {
		require.NoError(t, os.WriteFile(disk, []byte("disk"), 0o600))
	}
	tests := []struct {
		name  string
		leg   leg
		setup func(t *testing.T, flags *clientServerFlags, cmds *commandFake, vms *vmFake)
		outer string
		inner string
	}{
		{"server work dir", serverOnly, func(t *testing.T, fl *clientServerFlags, _ *commandFake, _ *vmFake) {
			fl.serverWorkDir = underFile(t)
		}, "server VM failed", "failed to create server work directory"},
		{"server boot", serverOnly, func(t *testing.T, fl *clientServerFlags, _ *commandFake, vms *vmFake) {
			fl.skipInstall = true
			installed(t, fl.serverDisk)
			vms.startErr = errHost
		}, "server VM failed", "server boot failed"},
		{"server boot TPM", serverOnly, func(t *testing.T, fl *clientServerFlags, _ *commandFake, vms *vmFake) {
			fl.skipInstall = true
			installed(t, fl.serverDisk)
			vms.tpmErr = errHost
		}, "server VM failed", "failed to setup server TPM for boot"},
		{"background server VM", background, func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.newErr = errHost
		}, "server VM failed", "failed to create server VM"},
		{"background server start", background, func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.startErr = errHost
		}, "server VM failed", "failed to start server VM"},
		{"client work dir", clientOnly, func(t *testing.T, fl *clientServerFlags, _ *commandFake, _ *vmFake) {
			fl.clientWorkDir = underFile(t)
		}, "client VM failed", "failed to create client work directory"},
		{"client boot TPM", clientOnly, func(t *testing.T, fl *clientServerFlags, _ *commandFake, vms *vmFake) {
			fl.skipInstall = true
			installed(t, fl.clientDisk)
			vms.tpmErr = errHost
		}, "client VM failed", "failed to setup client TPM for boot"},
		{"user work dir", userNetwork, func(t *testing.T, fl *clientServerFlags, _ *commandFake, _ *vmFake) {
			fl.serverWorkDir = underFile(t)
		}, "failed to create server work directory", ""},
		{"user config", userNetwork, func(t *testing.T, fl *clientServerFlags, _ *commandFake, _ *vmFake) {
			fl.serverConfigPath = filepath.Join(t.TempDir(), "absent.yaml")
		}, "failed to read server platform config", ""},
		{"user disk", userNetwork, func(_ *testing.T, _ *clientServerFlags, cmds *commandFake, _ *vmFake) {
			cmds.errs["qemu-img"] = errHost
		}, "failed to create server disk", ""},
		{"user install TPM", userNetwork, func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.tpmErr = errHost
		}, "failed to setup server TPM", ""},
		{"user install", userNetwork, func(_ *testing.T, _ *clientServerFlags, _ *commandFake, vms *vmFake) {
			vms.startErr = errHost
		}, "server installation failed", ""},
		{"user boot TPM", userNetwork, func(_ *testing.T, fl *clientServerFlags, _ *commandFake, vms *vmFake) {
			fl.skipInstall = true
			vms.tpmErr = errHost
		}, "failed to setup server TPM for boot", ""},
		{"user server VM", userNetwork, func(_ *testing.T, fl *clientServerFlags, _ *commandFake, vms *vmFake) {
			fl.skipInstall = true
			vms.newErr = errHost
		}, "failed to create server VM", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFirmware(t)
			f := withCSFake(t)
			withPipelineFake(t)
			cmds := withCommandFake(t)
			vms := withInstallingVMs(t)
			flags := csFlagsFor(t)
			switch tt.leg {
			case serverOnly:
				flags.serverOnly = true
			case background:
				flags.skipInstall = true
			case clientOnly:
				f.exists = true
				flags.clientOnly = true
				csServerCABundlePath = filepath.Join(t.TempDir(), "ca-bundle.pem")
			case userNetwork:
				flags.userNetwork, flags.serverOnly = true, true
				cmds.errs["nc"] = errHost
			}
			tt.setup(t, flags, cmds, vms)

			err := runClientServerTest(getTestFlags(), flags)
			var outer *WrappedError
			require.ErrorAs(t, err, &outer)
			assert.Equal(t, tt.outer, outer.Msg)
			if tt.inner != "" {
				var inner *WrappedError
				require.True(t, errors.As(outer.Err, &inner), "the leg's own error is kept")
				assert.Equal(t, tt.inner, inner.Msg)
			}
			assert.Nil(t, csServerState, "no server is left running")
		})
	}
}

// fakePXEEnv is the PXE test's network and server, kept in memory.
type fakePXEEnv struct {
	setupErr error
	startErr error
	ready    chan struct{}
	cleanups int
	stops    int
}

func (e *fakePXEEnv) Setup() error { return e.setupErr }
func (e *fakePXEEnv) Start(ctx context.Context) error {
	if e.startErr != nil {
		return e.startErr
	}
	<-ctx.Done()
	return nil
}
func (e *fakePXEEnv) Ready() <-chan struct{} { return e.ready }
func (e *fakePXEEnv) Stop() error            { e.stops++; return nil }
func (e *fakePXEEnv) Cleanup() error         { e.cleanups++; return nil }
func (e *fakePXEEnv) TapName() string        { return "tap-pxe0" }
func (e *fakePXEEnv) ServerIP() net.IP       { return net.IPv4(10, 99, 99, 1) }

type pxeFake struct {
	env     *fakePXEEnv
	configs []*ipxe.TestEnvConfig
	newErr  error
}

func withPXEFake(t *testing.T) *pxeFake {
	t.Helper()
	ready := make(chan struct{})
	close(ready)
	f := &pxeFake{env: &fakePXEEnv{ready: ready}}
	euid, newEnv, timeout := hostEUID, newPXETestEnv, pxeServerReadyTimeout
	t.Cleanup(func() { hostEUID, newPXETestEnv, pxeServerReadyTimeout = euid, newEnv, timeout })
	hostEUID = func() int { return 0 }
	newPXETestEnv = func(cfg *ipxe.TestEnvConfig, _ *logging.Logger) (pxeTestEnv, error) {
		f.configs = append(f.configs, cfg)
		if f.newErr != nil {
			return nil, f.newErr
		}
		return f.env, nil
	}
	return f
}

// pxeWorkDirWithNVRAM returns a PXE work dir whose OVMF NVRAM already
// exists, as it does after a first run.
func pxeWorkDirWithNVRAM(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	nvram := (&qemu.Config{WorkDir: workDir, Arch: qemu.ArchX86_64}).GetNVRAMPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(nvram), 0o755))
	require.NoError(t, os.WriteFile(nvram, []byte("nvram"), 0o600))
	return workDir
}

func TestHostSeams_RunTestPXE(t *testing.T) {
	const kernelURL, initrdURL = "http://10.99.99.1/vmlinuz", "http://10.99.99.1/initramfs"

	t.Run("boots from the network", func(t *testing.T) {
		pxe := withPXEFake(t)
		vms := withVMFake(t)
		workDir := pxeWorkDirWithNVRAM(t)
		withPXEFlags(t, kernelURL, initrdURL, "", "", workDir)

		require.NoError(t, runTestPXE(getTestFlags(), nil, nil))

		require.Len(t, pxe.configs, 1)
		require.Len(t, pxe.configs[0].BootEntries, 1)
		assert.Equal(t, kernelURL, pxe.configs[0].BootEntries[0].Kernel)
		assert.Equal(t, filepath.Join(workDir, "pxe-files"), pxe.configs[0].LocalFilesDir)
		require.Len(t, vms.configs, 1)
		assert.True(t, vms.configs[0].PXEEnabled)
		assert.Equal(t, "tap-pxe0", vms.configs[0].TapDevice)
		assert.Equal(t, []string{string(qemu.BootModePXE)}, vms.modes)
		assert.Equal(t, 1, vms.disks, "the client disk is prepared")
		assert.Equal(t, 1, vms.waits)
		assert.Equal(t, 1, pxe.env.stops)
		assert.Equal(t, 1, pxe.env.cleanups)
		assert.Equal(t, 1, vms.tpmStops)
	})

	t.Run("needs root", func(t *testing.T) {
		withPXEFake(t)
		hostEUID = func() int { return 1000 }
		err := runTestPXE(getTestFlags(), nil, nil)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Contains(t, msg.Msg, "requires root privileges")
	})

	failures := []struct {
		name  string
		setup func(p *pxeFake, vms *vmFake)
		msg   string
	}{
		{"environment", func(p *pxeFake, _ *vmFake) { p.newErr = errHost }, "failed to create PXE test environment"},
		{"network", func(p *pxeFake, _ *vmFake) { p.env.setupErr = errHost }, "failed to setup isolated network"},
		{"PXE server", func(p *pxeFake, _ *vmFake) { p.env.startErr = errHost; p.env.ready = nil }, "PXE server not ready"},
		{"TPM", func(_ *pxeFake, vms *vmFake) { vms.tpmErr = errHost }, "failed to setup TPM"},
		{"VM", func(_ *pxeFake, vms *vmFake) { vms.newErr = errHost }, "QEMU PXE boot failed"},
		{"disk", func(_ *pxeFake, vms *vmFake) { vms.diskErr = errHost }, "QEMU PXE boot failed"},
		{"start", func(_ *pxeFake, vms *vmFake) { vms.startErr = errHost }, "QEMU PXE boot failed"},
	}
	for _, tt := range failures {
		t.Run(tt.name+" fails", func(t *testing.T) {
			pxe := withPXEFake(t)
			vms := withVMFake(t)
			withPXEFlags(t, kernelURL, initrdURL, "", "", pxeWorkDirWithNVRAM(t))
			tt.setup(pxe, vms)
			err := runTestPXE(getTestFlags(), nil, nil)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.msg, wrapped.Msg)
			assert.ErrorIs(t, err, errHost)
		})
	}

	t.Run("key enrollment failure is logged and the boot goes on", func(t *testing.T) {
		pxe := withPXEFake(t)
		vms := withVMFake(t)
		withFirmware(t)
		vms.enroller.enrollErr = errHost
		workDir := pxeWorkDirWithNVRAM(t)
		require.NoError(t, os.MkdirAll(filepath.Join(workDir, "secure-boot-keys"), 0o755))
		withPXEFlags(t, kernelURL, initrdURL, "", "", workDir)
		secureBoot := pxeSecureBoot
		t.Cleanup(func() { pxeSecureBoot = secureBoot })
		pxeSecureBoot = true

		require.NoError(t, runTestPXE(getTestFlags(), nil, nil))

		assert.Equal(t, 1, vms.enroller.enrolls, "enrollment is attempted")
		require.Len(t, vms.configs, 1)
		assert.True(t, vms.configs[0].SecureBoot)
		assert.Equal(t, []string{string(qemu.BootModePXE)}, vms.modes, "the VM still boots from the network")
		assert.Equal(t, 1, pxe.env.stops)
	})

	t.Run("PXE server never ready", func(t *testing.T) {
		pxe := withPXEFake(t)
		pxe.env.ready = nil
		pxeServerReadyTimeout = time.Millisecond
		withVMFake(t)
		withPXEFlags(t, kernelURL, initrdURL, "", "", pxeWorkDirWithNVRAM(t))
		err := runTestPXE(getTestFlags(), nil, nil)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "PXE server not ready after 1ms", msg.Msg)
		assert.Equal(t, 1, pxe.env.cleanups, "the network is torn down")
	})

	t.Run("work dir under a file", func(t *testing.T) {
		pxe := withPXEFake(t)
		vms := withVMFake(t)
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		withPXEFlags(t, kernelURL, initrdURL, "", "", filepath.Join(file, "work"))
		err := runTestPXE(getTestFlags(), nil, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create work directory", wrapped.Msg)
		assert.Empty(t, vms.modes, "no VM boots without its work directory")
		assert.Empty(t, pxe.configs, "no PXE environment is built without its work directory")
	})
}

// withPXEWatch sets --expect and --serial-log for one test.
func withPXEWatch(t *testing.T, expect, serialLog string) {
	t.Helper()
	origExpect, origLog := pxeExpect, pxeSerialLog
	t.Cleanup(func() { pxeExpect, pxeSerialLog = origExpect, origLog })
	pxeExpect, pxeSerialLog = expect, serialLog
}

func TestHostSeams_RunTestPXEExpect(t *testing.T) {
	const kernelURL, initrdURL = "http://10.99.99.1/vmlinuz", "http://10.99.99.1/initramfs"

	t.Run("milestone in the serial log ends the run", func(t *testing.T) {
		withPXEFake(t)
		vms := withVMFake(t)
		withPXEFlags(t, kernelURL, initrdURL, "", "", pxeWorkDirWithNVRAM(t))
		serialLog := filepath.Join(t.TempDir(), "serial.log")
		require.NoError(t, os.WriteFile(serialLog, []byte("Welcome\nlocalhost login: "), 0o600))
		withPXEWatch(t, "login:", serialLog)

		require.NoError(t, runTestPXE(getTestFlags(), nil, nil))

		require.Len(t, vms.configs, 1)
		assert.False(t, vms.configs[0].SerialConsole, "the console goes to the watched log")
		assert.Equal(t, serialLog, vms.configs[0].SerialLogFile)
		assert.Equal(t, 1, vms.stops, "the VM is stopped once the milestone appears")
		assert.Zero(t, vms.waits, "an automated run does not wait on the VM")
	})

	t.Run("serial log cannot be read", func(t *testing.T) {
		withPXEFake(t)
		vms := withVMFake(t)
		withPXEFlags(t, kernelURL, initrdURL, "", "", pxeWorkDirWithNVRAM(t))
		withPXEWatch(t, "login:", t.TempDir())

		err := runTestPXE(getTestFlags(), nil, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "QEMU PXE boot failed", wrapped.Msg)
		var wait *WrappedError
		require.True(t, errors.As(wrapped.Err, &wait))
		assert.Equal(t, `waiting for "login:"`, wait.Msg)
		assert.Equal(t, 1, vms.stops, "the VM is stopped even when the watch fails")
	})

	t.Run("expect without a serial log", func(t *testing.T) {
		pxe := withPXEFake(t)
		withPXEFlags(t, kernelURL, initrdURL, "", "", t.TempDir())
		withPXEWatch(t, "login:", "")

		err := runTestPXE(getTestFlags(), nil, nil)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "--expect needs --serial-log to watch", msg.Msg)
		assert.Empty(t, pxe.configs, "no network is built")
	})

	t.Run("work dir under a file", func(t *testing.T) {
		pxe := withPXEFake(t)
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		withPXEFlags(t, kernelURL, initrdURL, "", "", filepath.Join(file, "work"))

		err := runTestPXE(getTestFlags(), nil, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create work directory", wrapped.Msg)
		assert.Empty(t, pxe.configs)
	})

	t.Run("half a direct boot entry", func(t *testing.T) {
		withPXEFake(t)
		withPXEFlags(t, kernelURL, "", "", "", t.TempDir())

		err := runTestPXE(getTestFlags(), nil, nil)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to resolve boot entry", wrapped.Msg)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "both --kernel and --initrd must be specified together", msg.Msg)
	})
}

func TestHostSeams_ResolveBootEntryFromISO(t *testing.T) {
	logger := createTestLogger(false)
	iso := filepath.Join(t.TempDir(), "alpine.iso")
	require.NoError(t, os.WriteFile(iso, []byte("iso"), 0o600))

	// extracted emulates 7z or bsdtar unpacking the given boot files.
	extracted := func(t *testing.T, workDir string, files map[string]string) func([]string) {
		return func([]string) {
			boot := filepath.Join(workDir, "iso-extract", "boot")
			require.NoError(t, os.MkdirAll(boot, 0o755))
			for name, content := range files {
				require.NoError(t, os.WriteFile(filepath.Join(boot, name), []byte(content), 0o600))
			}
		}
	}

	t.Run("lts files with the ISO cmdline", func(t *testing.T) {
		workDir := t.TempDir()
		withPXEFlags(t, "", "", "", iso, workDir)
		cmds := withCommandFake(t)
		cmds.onRun = extracted(t, workDir, map[string]string{
			"vmlinuz-lts": "k", "initramfs-lts": "i", "cmdline.txt": "console=ttyS0",
		})
		entry, err := resolveBootEntry(logger)
		require.NoError(t, err)
		extractDir := filepath.Join(workDir, "iso-extract")
		assert.Equal(t, "file://"+filepath.Join(extractDir, "boot", "vmlinuz-lts"), entry.Kernel)
		assert.Equal(t, "file://"+filepath.Join(extractDir, "boot", "initramfs-lts"), entry.Initrd)
		assert.Equal(t, "console=ttyS0", entry.Args)
		assert.Equal(t, [][]string{{"7z", "x", iso, "-o" + extractDir}}, cmds.argv)
	})

	t.Run("plain names, default args, bsdtar fallback", func(t *testing.T) {
		workDir := t.TempDir()
		withPXEFlags(t, "", "", "", iso, workDir)
		cmds := withCommandFake(t)
		cmds.errs["7z"] = errHost
		cmds.onRun = extracted(t, workDir, map[string]string{"vmlinuz": "k", "initramfs": "i"})
		entry, err := resolveBootEntry(logger)
		require.NoError(t, err)
		assert.Equal(t, "file://"+filepath.Join(workDir, "iso-extract", "boot", "vmlinuz"), entry.Kernel)
		assert.Contains(t, entry.Args, "console=ttyS0,115200")
		require.Len(t, cmds.argv, 2)
		assert.Equal(t, "bsdtar", cmds.argv[1][0])
	})

	t.Run("no kernel in the ISO", func(t *testing.T) {
		workDir := t.TempDir()
		withPXEFlags(t, "", "", "", iso, workDir)
		withCommandFake(t)
		_, err := resolveBootEntry(logger)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "kernel not found in ISO (tried boot/vmlinuz-lts and boot/vmlinuz)", msg.Msg)
	})

	t.Run("no initrd in the ISO", func(t *testing.T) {
		workDir := t.TempDir()
		withPXEFlags(t, "", "", "", iso, workDir)
		cmds := withCommandFake(t)
		cmds.onRun = extracted(t, workDir, map[string]string{"vmlinuz-lts": "k"})
		_, err := resolveBootEntry(logger)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "initrd not found in ISO (tried boot/initramfs-lts and boot/initramfs)", msg.Msg)
	})

	t.Run("no extractor works", func(t *testing.T) {
		withPXEFlags(t, "", "", "", iso, t.TempDir())
		cmds := withCommandFake(t)
		cmds.errs["7z"], cmds.errs["bsdtar"] = errHost, errHost
		_, err := resolveBootEntry(logger)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to extract ISO", wrapped.Msg)
		assert.ErrorIs(t, err, errHost)
	})
}
