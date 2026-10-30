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
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// The host boundary of the iso commands. Every external process, VM,
// software TPM, network and ISO pipeline step goes through one of these
// unexported vars. Their defaults are the real host calls and production
// code never reassigns them; unit tests swap them to stay in memory.

// Processes: qemu-img, ping, nc, dig, 7z, bsdtar and make.
var (
	runHostCommand    = func(cmd *exec.Cmd) error { return cmd.Run() }
	hostCommandOutput = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }
	hostEUID          = os.Geteuid
)

// The ISO pipeline: Alpine download, extraction, Secure Boot keys,
// customization and the final xorriso build.
var (
	isoDownload             = pkgiso.DownloadISO
	isoExtract              = pkgiso.ExtractISO
	isoEnsureSecureBootKeys = pkgiso.EnsureSecureBootKeys
	isoCustomize            = func(ctx context.Context, cfg *pkgiso.PlatformISOConfig, logger *logging.Logger) error {
		return pkgiso.NewCustomizer(cfg, logger).CustomizeAll(ctx)
	}
	isoBuild = func(ctx context.Context, logger *logging.Logger, cfg *pkgiso.ISOConfig) error {
		return pkgiso.NewBuilder(logger).BuildISO(ctx, cfg)
	}
)

// QEMU virtual machines and the swtpm software TPM. defaultQEMUConfig
// carries the host's OVMF firmware paths and probes for the br-int bridge.
var (
	defaultQEMUConfig = qemu.DefaultConfig
	newQEMUVM     = qemu.NewVM
	vmStart       = (*qemu.VM).Start
	vmWait        = (*qemu.VM).Wait
	vmStop        = (*qemu.VM).Stop
	vmCreateDisk  = (*qemu.VM).CreateDisk
	vmIsRunning   = (*qemu.VM).IsRunning
	stopQEMUByTap = qemu.StopExistingByTap
	startTPM      = harness.StartTPM
	stopTPM       = harness.StopTPM

	newSecureBootEnroller = func(cfg *qemu.SecureBootEnrollerConfig, logger *logging.Logger) (secureBootEnroller, error) {
		enroller, err := qemu.NewSecureBootEnroller(cfg, logger)
		if err != nil {
			return nil, err
		}
		return enroller, nil
	}
)

// secureBootEnroller is the part of qemu.SecureBootEnroller the tests use.
type secureBootEnroller interface {
	IsEnrolled() bool
	EnrollKeys(ctx context.Context) error
}

// seamedVM adapts a *qemu.VM to bootVM through the VM seams.
type seamedVM struct{ vm *qemu.VM }

func (s seamedVM) Wait() error { return vmWait(s.vm) }
func (s seamedVM) Stop() error { return vmStop(s.vm) }

// The client-server test's isolated network (bridge, TAPs, OVS, NAT).
var (
	csCheckRoot         = testenv.CheckRootPrivileges
	csOVSAvailable      = testenv.IsOVSAvailable
	csNetworkExists     = testenv.NetworkExists
	csCleanupStale      = testenv.CleanupStaleResources
	csNewLinuxNetwork   = func(cfg *testenv.NetworkConfig) testenv.IsolatedNetwork { return testenv.NewIsolatedNetwork(cfg) }
	csNewOVSNetwork     = newOVSNetwork
	csReadyPollInterval = 2 * time.Second
	csMinBootTime       = 30 * time.Second
	csStatusDo          = (*http.Client).Do
)

func newOVSNetwork(cfg *testenv.NetworkConfig, opts *testenv.OVSNetworkOptions) (testenv.IsolatedNetwork, error) {
	network, err := testenv.NewOVSIsolatedNetwork(cfg, opts)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// pxeTestEnv is the part of ipxe.TestEnv the PXE test drives.
type pxeTestEnv interface {
	Setup() error
	Start(ctx context.Context) error
	Ready() <-chan struct{}
	Stop() error
	Cleanup() error
	TapName() string
	ServerIP() net.IP
}

// The PXE test's isolated network and PXE server (DHCP, TFTP, HTTP).
var (
	newPXETestEnv = func(cfg *ipxe.TestEnvConfig, logger *logging.Logger) (pxeTestEnv, error) {
		env, err := ipxe.NewTestEnv(cfg, logger)
		if err != nil {
			return nil, err
		}
		return env, nil
	}
	pxeServerReadyTimeout = 10 * time.Second
)
