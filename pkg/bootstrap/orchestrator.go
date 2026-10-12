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

package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

const (
	// defaultHealthInterval is the polling interval for node health checks.
	defaultHealthInterval = 5 * time.Second

	// defaultControlPlaneHealthGateTimeout is the maximum time to wait for all
	// control-plane nodes to pass health checks before proceeding to teardown.
	defaultControlPlaneHealthGateTimeout = 5 * time.Minute

	// phaseDiscovery is the name of the discovery phase.
	phaseDiscovery = "discovery"

	// phaseSwitch is the name of the switch configuration phase.
	phaseSwitch = "switch"

	// phaseDeploy is the name of the container deployment phase.
	phaseDeploy = "deploy"

	// phaseControlPlane is the name of the control plane provisioning phase.
	phaseControlPlane = "control-plane"

	// phaseSeed is the name of the template seeding phase.
	phaseSeed = "seed"

	// phaseRemaining is the name of the remaining node provisioning phase.
	phaseRemaining = "remaining-nodes"

	// phaseBMCEnroll is the name of the BMC enrollment phase that runs after
	// all nodes have been provisioned. Enrollment is non-fatal: per-node
	// failures are recorded in BootstrapResult.BMCEnrollments and logged as
	// warnings but do not abort the deployment.
	phaseBMCEnroll = "bmc-enroll"

	// phaseHealthGate is the name of the control-plane health verification
	// phase that runs before teardown.
	phaseHealthGate = "health-gate"

	// phaseTeardown is the name of the container teardown phase.
	phaseTeardown = "teardown"

	// nodeStatusDiscovered is the status for a discovered node.
	nodeStatusDiscovered = "discovered"

	// nodeStatusProvisioning is the status for a node being provisioned.
	nodeStatusProvisioning = "provisioning"

	// nodeStatusInstalled is the status for a successfully installed node.
	nodeStatusInstalled = "installed"

	// nodeStatusFailed is the status for a failed node.
	nodeStatusFailed = "failed"

	// nodeStatusSkipped is the status for a node whose install was skipped
	// because SkipInstall is true.
	nodeStatusSkipped = "skipped"

	// bmcEnrollPath is the REST path template for the BMC enrollment endpoint.
	// The profile ID is interpolated as the single format argument.
	bmcEnrollPath = "/api/v1/bmc/%d/enroll"

	// bmcBackupDirMode is the permissions used when creating per-node backup
	// directories under BackupsDir.
	bmcBackupDirMode = 0700

	// bmcBackupFileMode is the permissions used when writing per-node backup
	// files.
	bmcBackupFileMode = 0600
)

// BMCEnrollOutcome records the result of a single-node BMC enrollment attempt
// during the bmc-enroll phase.
type BMCEnrollOutcome struct {
	// Hostname identifies the node that was enrolled (or attempted).
	Hostname string `json:"hostname" yaml:"hostname"`

	// ProfileID is the device-profile ID used as the path parameter when
	// calling POST /api/v1/bmc/{profileID}/enroll.
	ProfileID uint64 `json:"profile_id" yaml:"profile_id"`

	// OK is true when the enrollment POST returned a success status.
	OK bool `json:"ok" yaml:"ok"`

	// Detail holds a human-readable description of the outcome. On success
	// this is empty; on failure it contains the error message.
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

// BootstrapResult holds the outcome of a complete bootstrap run.
type BootstrapResult struct {
	Phase             string             `json:"phase" yaml:"phase"`
	Nodes             []NodeResult       `json:"nodes" yaml:"nodes"`
	SwitchConfigured  bool               `json:"switch_configured" yaml:"switch_configured"`
	ContainerDeployed bool               `json:"container_deployed" yaml:"container_deployed"`
	ContainerTornDown bool               `json:"container_torn_down" yaml:"container_torn_down"`
	ControlPlaneReady bool               `json:"control_plane_ready" yaml:"control_plane_ready"`
	GatewaysReady     bool               `json:"gateways_ready" yaml:"gateways_ready"`
	WorkersReady      bool               `json:"workers_ready" yaml:"workers_ready"`
	BMCEnrollments    []BMCEnrollOutcome `json:"bmc_enrollments,omitempty" yaml:"bmc_enrollments,omitempty"`
	Duration          time.Duration      `json:"duration" yaml:"duration"`
}

// NodeResult holds the bootstrap outcome for a single node.
type NodeResult struct {
	Hostname   string   `json:"hostname" yaml:"hostname"`
	Role       string   `json:"role" yaml:"role"`
	MACs       []string `json:"macs" yaml:"macs"`
	BMCManaged bool     `json:"bmc_managed" yaml:"bmc_managed"`
	Status     string   `json:"status" yaml:"status"`
	Error      string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// Deployer deploys and tears down the bootstrap container.
type Deployer interface {
	// Deploy starts the bootstrap container with the given manifest.
	Deploy(ctx context.Context, manifest *container.Manifest) error

	// Teardown stops and removes the bootstrap container.
	Teardown(ctx context.Context) error
}

// HealthChecker tests whether a node is healthy.
// ServerNameHealthChecker is implemented by health checkers that can
// verify the probed endpoint's certificate against an expected DNS name
// while dialing it by address. The control plane is dialed by IP and its
// certificate names only its DNS identity, so its probe needs this.
type ServerNameHealthChecker interface {
	CheckServerName(ctx context.Context, address, serverName string) error
}

type HealthChecker interface {
	// Check returns nil when the node at the given address is healthy.
	Check(ctx context.Context, address string) error
}

// ConfigServerReadiness reports whether the bootstrap container's HTTP
// config endpoint is actually serving.
//
// It exists as a seam because "the container is up" and "the service is
// up" are different facts, and the deploy phase can only observe the
// second by asking. The production implementation polls /health.
type ConfigServerReadiness interface {
	// WaitReady returns nil once the config server at baseURL answers
	// /health, and an error when it does not within the probe's own
	// bound or the context's, whichever is shorter.
	WaitReady(ctx context.Context, baseURL string) error

	// WaitDeviceScriptReady returns nil once the device-script server
	// at baseURL answers with a boot script.
	//
	// It asks for a script rather than merely dialling the port,
	// because the container runs with --net=host: the failure being
	// guarded against is another service already owning that port, and
	// that service would answer a dial perfectly happily.
	WaitDeviceScriptReady(ctx context.Context, baseURL string) error
}

// httpConfigServerReadiness is the production ConfigServerReadiness: it
// polls the container's /health over HTTP.
type httpConfigServerReadiness struct{}

// WaitReady implements ConfigServerReadiness.
func (httpConfigServerReadiness) WaitReady(ctx context.Context, baseURL string) error {
	return waitForHTTPConfigServerReady(ctx, baseURL)
}

// WaitDeviceScriptReady implements ConfigServerReadiness.
func (httpConfigServerReadiness) WaitDeviceScriptReady(ctx context.Context, baseURL string) error {
	return waitForDeviceScriptServer(ctx, baseURL)
}

// OrchestratorParams holds the dependencies for creating an Orchestrator.
type OrchestratorParams struct {
	Config        *BootstrapConfig
	ConfigPath    string // Path to the bootstrap YAML file, used to resolve relative template paths.
	BMCFactory    bmc.ClientFactory
	Logger        *slog.Logger
	Deployer      Deployer
	HealthChecker HealthChecker
	// ConfigServerReadiness probes whether the deployed container is
	// actually serving before the deploy phase reports success. Nil
	// selects the real HTTP probe; it is injectable for the same
	// reason Deployer and HealthChecker are, so tests can drive the
	// phase without a container. It is never nil at runtime, because a
	// nil probe would silently restore the fail-open behaviour this
	// gate exists to remove.
	ConfigServerReadiness ConfigServerReadiness
	// TrustConfig is the platform trust configuration. When non-nil and the
	// BMC scope is configured, the orchestrator constructs a run-scoped
	// TLSProvider and threads it into every bmc.Config so BMC connections
	// use the trust resolver. When nil, BMC connections fall back to
	// system roots with TLS 1.2+ minimum (the BuildTLSConfig secure default).
	TrustConfig *trust.Config
	// SkipVirtualMediaMount mirrors Orchestrator.SkipVirtualMediaMount.
	SkipVirtualMediaMount bool
}

// Orchestrator runs the complete network bootstrap flow.
type Orchestrator struct {
	config            *BootstrapConfig
	configDir         string // Directory containing the bootstrap YAML, for resolving relative paths.
	discovered        []DiscoveredNode
	logger            *slog.Logger
	bmcFactory        bmc.ClientFactory
	deployer          Deployer
	healthChk         HealthChecker
	configServerReady ConfigServerReadiness
	bmcTLSProvider    bmc.TLSProvider // run-scoped TLS provider for BMC connections; nil ⇒ system roots
	trustConfig       *trust.Config   // base trust config; merged with per-node bmc_spki_pin/bmc_trust for node-scoped BMC TLS

	// cpCAPool is populated after the control-plane CA bundle is successfully
	// fetched via fetchControlPlaneCABundle (capture-then-verify). Once set,
	// the seeder and health checker verify the CP's TLS certificate against
	// this pool rather than relying on the system pool. Guarded by cpCAMu:
	// control-plane nodes are provisioned concurrently and each one's
	// post-install health wait reaches for the pool.
	cpCAPool *x509.CertPool
	cpCAMu   sync.Mutex
	// cpCAFetchGate serializes capture attempts so concurrent waiters do
	// not each fetch the bundle; a waiter that acquires it after another
	// succeeded finds the pool cached and makes no request. It is a
	// one-slot semaphore rather than a mutex so a queued waiter can still
	// honor its own context while another holds it.
	cpCAFetchGate     chan struct{}
	cpCAFetchGateOnce sync.Once

	// cpTLSName is the DNS name the control plane's webservice certificate
	// is verified against by every TLS client that dials it by address;
	// see controlPlaneTLSName. Resolved once.
	cpTLSName     string
	cpTLSNameErr  error
	cpTLSNameOnce sync.Once

	// pollTicker builds the tickers the orchestrator's wait loops poll on
	// (health, power-state verification). nil means newPollTicker (a real
	// time.Ticker); tests substitute a fake so the poll cadence is driven,
	// not waited for.
	pollTicker func(interval time.Duration) (tick <-chan time.Time, stop func())

	// mediaReadWindow bounds how long a virtual-media boot waits for the
	// host to open the ISO before concluding the firmware never booted the
	// media. Zero means defaultMediaReadWindow.
	mediaReadWindow time.Duration

	// bootProbeWindow bounds how long a virtual-media boot waits for the
	// install log after the media was read. Zero means bootProbeTimeout.
	bootProbeWindow time.Duration

	// mediaReadHTTPClient is the HTTP client the media-read probe polls
	// /media/status with. nil means the probe's default (a ten-second
	// timeout on the default transport); tests substitute one whose
	// exchanges the media-read window cannot cut short (#262).
	mediaReadHTTPClient *http.Client

	// consoleOpener opens a node's serial console for the transcript a
	// virtual-media boot attempt records. nil means openSOLConsole (SOL
	// on a dedicated BMC client); tests substitute a reader they feed.
	consoleOpener consoleOpener

	// forensicRetryDelay spaces the attempts of a forensic upload. Zero
	// means forensicUploadRetryDelay; tests shorten it so the retry
	// behaviour is exercised without paying for the pause.
	forensicRetryDelay time.Duration

	// SkipVirtualMediaMount lets operators bypass MountVirtualMedia for
	// boot_method: virtual-media nodes when the BMC needs an out-of-band
	// mount path the orchestrator doesn't yet support natively (e.g.
	// Supermicro X10 boards whose write API is gated behind a DCMS license,
	// or whose only working mount path is the legacy CGI op.cgi flow that
	// the smc-cgi backend documents as a stub pending HAR capture).
	//
	// When true, the orchestrator skips the Mount step and assumes the
	// operator has already inserted the correct ISO via vendor tooling or
	// the iKVM HTML5 console. SetBootDevice + power reset + wait-for-health
	// + best-effort Unmount still run normally. This is the documented
	// escape hatch -- see docs/bootstrap/virtual-media.md.
	SkipVirtualMediaMount bool
}

// NewOrchestrator creates an Orchestrator from the given parameters.
func NewOrchestrator(params OrchestratorParams) (*Orchestrator, error) {
	if params.Config == nil {
		return nil, ErrNilOrchestratorConfig{}
	}
	if params.BMCFactory == nil {
		return nil, ErrNilBMCFactory{}
	}
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}
	configServerReady := params.ConfigServerReadiness
	if configServerReady == nil {
		configServerReady = httpConfigServerReadiness{}
	}
	healthChk := params.HealthChecker
	if healthChk == nil {
		hc := newHTTPHealthChecker(logger, nil)
		// Wire the pxeboot base URL so the checker can consult the
		// node-uploaded registration.json as the authoritative signal
		// that platformd is actually running, instead of guessing at
		// webservice ports.
		if url, err := installLogBaseURL(&params.Config.Deployer); err == nil {
			hc.WithPxebootURL(url)
		}
		healthChk = hc
	}
	configDir := ""
	if params.ConfigPath != "" {
		configDir = filepath.Dir(params.ConfigPath)
	}
	// Build run-scoped BMC TLS provider when a trust config with a BMC
	// scope is provided. A single provider is shared across all nodes so
	// re-contacted BMCs verify against previously captured TOFU pins.
	var bmcTLSProv bmc.TLSProvider
	if params.TrustConfig != nil {
		p, _, err := NewBootstrapBMCTLSProvider(params.TrustConfig, logger)
		if err != nil {
			return nil, err
		}
		bmcTLSProv = p
	}

	return &Orchestrator{
		config:                params.Config,
		configDir:             configDir,
		logger:                logger,
		bmcFactory:            params.BMCFactory,
		deployer:              params.Deployer,
		healthChk:             healthChk,
		configServerReady:     configServerReady,
		bmcTLSProvider:        bmcTLSProv,
		trustConfig:           params.TrustConfig,
		SkipVirtualMediaMount: params.SkipVirtualMediaMount,
	}, nil
}

// Run executes the complete bootstrap flow and returns the aggregate result.
func (o *Orchestrator) Run(ctx context.Context) (*BootstrapResult, error) {
	result := &BootstrapResult{}
	start := time.Now()

	// Phases 0-2: discovery, switch configuration, the bootstrap container.
	if err := o.bringUpContainer(ctx, result); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	// Phase 3: PXE boot control plane nodes.
	result.Phase = phaseControlPlane
	if err := o.provisionControlPlane(ctx, result); err != nil {
		result.Duration = time.Since(start)
		return result, ErrBootstrapFailed{Phase: phaseControlPlane, Cause: err}
	}
	result.ControlPlaneReady = true

	// Phase 4: Seed templates and create profiles.
	result.Phase = phaseSeed
	seeder, err := o.seedTemplatesWithSeeder(ctx)
	if err != nil {
		result.Duration = time.Since(start)
		return result, ErrBootstrapFailed{Phase: phaseSeed, Cause: err}
	}

	// Phase 5: PXE boot gateway and worker nodes.
	result.Phase = phaseRemaining
	if err := o.provisionRemainingNodes(ctx, result); err != nil {
		result.Duration = time.Since(start)
		return result, ErrBootstrapFailed{Phase: phaseRemaining, Cause: err}
	}
	result.GatewaysReady = true
	result.WorkersReady = true

	// Phase 6: BMC enrollment (non-fatal, skipped when no node sets bmc_enroll).
	if o.hasBMCEnrollNodes() {
		result.Phase = phaseBMCEnroll
		o.runBMCEnroll(ctx, result, seeder)
	} else {
		o.logger.Debug("bootstrap: skipping bmc-enroll phase (no nodes with bmc_enroll: true)")
	}

	// Phase 7: Auto-teardown bootstrap container (non-fatal).
	if o.deployer != nil {
		// Health gate: verify all control-plane nodes are serving before
		// tearing down the bootstrap container. The container typically
		// provides DHCP/DNS -- removing it before the control-plane takes
		// over those services would leave every node without network.
		result.Phase = phaseHealthGate
		if err := o.controlPlaneHealthGate(ctx); err != nil {
			o.logger.Warn("bootstrap: control-plane health gate failed, skipping teardown to preserve network services",
				slog.String("error", err.Error()))
			// Do NOT tear down -- the bootstrap container may still be
			// the only provider of DHCP/DNS on the network.
		} else {
			result.Phase = phaseTeardown
			if err := o.teardownContainer(ctx); err != nil {
				o.logger.Warn("bootstrap container teardown failed",
					slog.String("error", err.Error()))
			} else {
				result.ContainerTornDown = true
			}
		}
	}

	result.Phase = "complete"
	result.Duration = time.Since(start)
	return result, nil
}

// Deploy runs the phases that bring the bootstrap container up —
// discovery, switch configuration when configured, and the container
// deploy with its serving check — exactly as Run does, then stops. It
// needs a deployer (deployer.host and deployer.container_image).
func (o *Orchestrator) Deploy(ctx context.Context) (*BootstrapResult, error) {
	if o.deployer == nil {
		return nil, ErrDeployerNotConfigured{}
	}
	result := &BootstrapResult{}
	start := time.Now()
	err := o.bringUpContainer(ctx, result)
	result.Duration = time.Since(start)
	return result, err
}

// Teardown stops and removes the bootstrap container and its staged data
// on the deployer host, as Run's last phase does.
func (o *Orchestrator) Teardown(ctx context.Context) error {
	if o.deployer == nil {
		return ErrDeployerNotConfigured{}
	}
	return o.teardownContainer(ctx)
}

// bringUpContainer runs Phases 0-2 into result: discovery, switch
// configuration, and the bootstrap container — deployed when there is a
// deployer, otherwise verified as the one the operator runs.
func (o *Orchestrator) bringUpContainer(ctx context.Context, result *BootstrapResult) error {
	// Phase 0: Discovery.
	result.Phase = phaseDiscovery
	discovered, err := o.discover(ctx)
	if err != nil {
		return ErrBootstrapFailed{Phase: phaseDiscovery, Cause: err}
	}
	o.discovered = discovered
	o.populateNodeResults(result)

	// Phase 1: Switch configuration (optional).
	if o.config.Switch != nil {
		result.Phase = phaseSwitch
		if err := o.configureSwitch(ctx); err != nil {
			return ErrBootstrapFailed{Phase: phaseSwitch, Cause: err}
		}
		result.SwitchConfigured = true
	}

	// Phase 2: Deploy bootstrap container.
	if o.deployer != nil {
		result.Phase = phaseDeploy
		if err := o.deployContainer(ctx); err != nil {
			return ErrBootstrapFailed{Phase: phaseDeploy, Cause: err}
		}
		result.ContainerDeployed = true
	} else if o.config.Deployer.Host != "" {
		// No deployer means the operator runs the bootstrap container
		// themselves (deployer.container_image empty), so Phase 2 is
		// skipped — but the run depends on that container exactly as
		// much, and skipping the phase used to skip the only check that
		// it is serving. Verify it here instead of provisioning into
		// the same silence. With no deployer host there is nothing to
		// point a probe at, and per-MAC staging is left to its
		// documented fall-back.
		result.Phase = phaseDeploy
		if err := o.verifyContainerServing(ctx); err != nil {
			return ErrBootstrapFailed{Phase: phaseDeploy, Cause: err}
		}
	}
	return nil
}

// Discover runs only Phase 0 (BMC discovery).
func (o *Orchestrator) Discover(ctx context.Context) ([]DiscoveredNode, error) {
	discovered, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	o.discovered = discovered
	return discovered, nil
}

// discover calls DiscoverNodes from the discovery module.
func (o *Orchestrator) discover(ctx context.Context) ([]DiscoveredNode, error) {
	o.logger.Info("bootstrap: starting node discovery",
		slog.Int("node_count", len(o.config.Nodes)))
	discovered, err := DiscoverNodes(ctx, o.config.Nodes, o.logger, DiscoveryOptions{
		TLSProvider:   o.bmcTLSProvider,
		ClientFactory: o.bmcFactory,
	})
	if err != nil {
		return nil, err
	}
	// The control plane's trust anchor is captured only from its
	// operator-declared static address, so a control plane without one
	// cannot be bootstrapped; say so at discovery, before any node is
	// touched further.
	for i := range discovered {
		if discovered[i].Role == RoleControlPlane && len(discovered[i].StaticIPv4s()) == 0 {
			return nil, ControlPlaneStaticIPRequiredError{Hostname: discovered[i].Hostname}
		}
	}
	return discovered, nil
}

// configureSwitch creates a switch configurator and applies configuration.
func (o *Orchestrator) configureSwitch(ctx context.Context) error {
	o.logger.Info("bootstrap: configuring switch",
		slog.String("vendor", o.config.Switch.Vendor))

	plan, err := o.config.NetworkPlan()
	if err != nil {
		return err
	}
	swConfig, err := buildSwitchConfig(o.config.Switch, plan)
	if err != nil {
		return err
	}
	configurator, err := switchmgmt.NewConfigurator(swConfig, o.logger)
	if err != nil {
		return err
	}
	defer configurator.Close()

	return configurator.Configure(ctx, swConfig)
}

// deployContainer builds a manifest from discovered nodes and deploys the container.
func (o *Orchestrator) deployContainer(ctx context.Context) error {
	o.logger.Info("bootstrap: deploying bootstrap container",
		slog.String("host", o.config.Deployer.Host))

	nodeInfos := toDiscoveredNodeInfos(o.discovered)
	manifest := container.BuildManifest(nodeInfos)
	if err := o.deployer.Deploy(ctx, manifest); err != nil {
		return ErrContainerDeployFailed{
			Host:  o.config.Deployer.Host,
			Cause: err,
		}
	}

	// A started container is not a running service, and this phase used
	// to report the first as if it were the second. `docker run -d`
	// printing an ID proves only that the container was created;
	// supervisord can retire pxeboot seconds later — a port conflict on
	// the deployer does exactly that — and the container stays Up with
	// nothing serving inside it. `docker inspect` agrees it is Running,
	// so state alone cannot tell the difference either. Only asking the
	// service can.
	//
	// This is deliberately fatal. The endpoint being probed is the
	// per-MAC config endpoint: with it dead, every node silently
	// installs from the ISO's baked config instead of its own, so the
	// run produces a whole fleet with the wrong identity while
	// reporting progress normally. Failing here is the difference
	// between one clear error and a reinstall.
	return o.verifyContainerServing(ctx)
}

// verifyContainerServing refuses to let the run proceed unless BOTH of
// the bootstrap container's listeners are up.
//
// Checking only the config server is not enough. The two listeners
// start in separate goroutines, and the probe returns on its first
// success, so a probe issued while the container is still coming up can
// see /health answer microseconds before the device-script bind fails —
// and the device-script bind is the one that fails, because it is the
// port an unrelated service on the deployer already owns. pxeboot does
// exit when either listener fails, so this is a startup race rather
// than a steady state, but a startup race is precisely what a probe
// fired immediately after `docker run` is exposed to.
//
// The device-script server has no /health of its own, so what is asked
// of it is a boot script — not merely a TCP accept, because the
// container runs with --net=host and the squatting service would answer
// a dial. Nothing else on a deployer answers /boot/device/{mac}.ipxe
// with an iPXE script.
func (o *Orchestrator) verifyContainerServing(ctx context.Context) error {
	baseURL, err := installLogBaseURL(&o.config.Deployer)
	if err != nil {
		return err
	}
	if err := o.configServerReady.WaitReady(ctx, baseURL); err != nil {
		return ErrContainerServiceNotServing{
			Host:     o.config.Deployer.Host,
			BaseURL:  baseURL,
			Listener: "config server",
			Cause:    err,
		}
	}

	host := o.config.Deployer.EffectiveSMBHost()
	devURL := "http://" + net.JoinHostPort(host, strconv.Itoa(o.config.Deployer.EffectiveBootstrapDeviceScriptPort()))
	if err := o.configServerReady.WaitDeviceScriptReady(ctx, devURL); err != nil {
		return ErrContainerServiceNotServing{
			Host:     o.config.Deployer.Host,
			BaseURL:  devURL,
			Listener: "device-script server",
			Cause:    err,
		}
	}

	o.logger.Info("bootstrap: container listeners are serving",
		slog.String("config_server", baseURL),
		slog.String("device_script_server", devURL))
	return nil
}

// provisionControlPlane provisions all control-plane nodes via BMC and waits
// for each to become healthy.
func (o *Orchestrator) provisionControlPlane(ctx context.Context, result *BootstrapResult) error {
	cpNodes := o.nodesByRole(RoleControlPlane)
	if len(cpNodes) == 0 {
		return ErrNoControlPlaneNode{}
	}

	o.logger.Info("bootstrap: provisioning control plane nodes",
		slog.Int("count", len(cpNodes)))

	return o.provisionNodes(ctx, cpNodes, result)
}

// provisionRemainingNodes provisions gateway and worker nodes.
func (o *Orchestrator) provisionRemainingNodes(ctx context.Context, result *BootstrapResult) error {
	remaining := make([]DiscoveredNode, 0)
	for i := range o.discovered {
		if o.discovered[i].Role != RoleControlPlane {
			remaining = append(remaining, o.discovered[i])
		}
	}

	if len(remaining) == 0 {
		o.logger.Info("bootstrap: no gateway or worker nodes to provision")
		return nil
	}

	o.logger.Info("bootstrap: provisioning remaining nodes",
		slog.Int("count", len(remaining)))

	return o.provisionNodes(ctx, remaining, result)
}

// provisionNodes provisions nodes in parallel and returns only once every
// one has finished, so a node that fails early never ends the phase — and
// with it the PXE and registration servers — under a sibling that is still
// installing. One failure is returned as is; several are returned together
// as ErrNodesProvisionFailed, in node order.
func (o *Orchestrator) provisionNodes(ctx context.Context, nodes []DiscoveredNode, result *BootstrapResult) error {
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Go(func() {
			errs[i] = o.provisionNode(ctx, &nodes[i], result)
		})
	}
	wg.Wait()

	failures := nonNilErrors(errs...)
	switch len(failures) {
	case 0:
		return nil
	case 1:
		return failures[0]
	default:
		return ErrNodesProvisionFailed{Failures: failures}
	}
}

// provisionNode handles a single node: BMC boot setup + health wait. The
// boot mechanism is selected per-node by NodeConfig.BootMethod:
//   - "" / "pxe"      -> existing PXE flow (bmcBootNode + waitForHealth)
//   - "virtual-media" -> bootNodeVirtualMedia (mounts ISO via SMB on the BMC,
//     sets one-shot CD boot, power-cycles, waits for health,
//     then unmounts on success)
//
// Nodes with SkipInstall set are marked installed immediately without any
// BMC interaction, ISO staging, or power cycling. They still participate in
// health checks and the seed phase.
func (o *Orchestrator) provisionNode(ctx context.Context, node *DiscoveredNode, result *BootstrapResult) error {

	// SkipInstall: the node is already deployed and running. Skip the
	// entire install flow (virtual media, PXE, BMC power control) and
	// mark it as installed so downstream phases (seed, health gate)
	// include it normally.
	if node.SkipInstall {
		o.logger.Info("bootstrap: skipping install for already-deployed node",
			slog.String("hostname", node.Hostname),
			slog.String("role", node.Role))
		o.updateNodeStatus(result, node.Hostname, nodeStatusSkipped, "")
		return nil
	}

	o.updateNodeStatus(result, node.Hostname, nodeStatusProvisioning, "")

	bootMethod := node.EffectiveBootMethod()
	if bootMethod != BootMethodVirtualMedia && bootMethod != BootMethodPXE {
		// Caught by config Validate(), but defend in depth.
		err := ErrInvalidBootMethod{Hostname: node.Hostname, Value: node.BootMethod}
		o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, err.Error())
		return ErrNodeProvisionFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

	fail := func(cause error) error {
		o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, cause.Error())
		return ErrNodeProvisionFailed{Hostname: node.Hostname, Role: node.Role, Cause: cause}
	}

	// Board-management gate. A node WITHOUT a management block (no BMC / no
	// future controller) gets ZERO hardware operations: the orchestrator
	// never touches power, boot device, or virtual media. Such a node is
	// PXE- or media-booted into the installer by its own boot order (or the
	// operator), installs, and self-boots the installed OS via the ISO's
	// after-install=reboot action. This is what lets the same automation
	// provision a Raspberry Pi or an unmanaged mini-PC alongside managed
	// servers. See BoardController / provisionUnmanaged.
	if !hasBoardManagement(&node.NodeConfig) {
		if bootMethod == BootMethodVirtualMedia {
			// Virtual media has nothing to mount the ISO with absent a
			// controller — this is a config error, defended here.
			return fail(ErrVirtualMediaRequiresBoardManagement{Hostname: node.Hostname})
		}
		if err := o.provisionUnmanaged(ctx, node); err != nil {
			return fail(err)
		}
		o.updateNodeStatus(result, node.Hostname, nodeStatusInstalled, "")
		return nil
	}

	// Managed node: drive the full install lifecycle through the board
	// controller. Both branches own their health wait and their own cleanup.
	switch bootMethod {
	case BootMethodVirtualMedia:
		if err := o.bootNodeVirtualMedia(ctx, node); err != nil {
			return fail(err)
		}
	case BootMethodPXE:
		if err := o.managedPXEProvision(ctx, node); err != nil {
			return fail(err)
		}
	}
	o.updateNodeStatus(result, node.Hostname, nodeStatusInstalled, "")
	return nil
}

// provisionUnmanaged provisions a node that has NO board management. The
// orchestrator performs zero hardware operations: it publishes the node's
// per-MAC installer config to the pxeboot HTTP server (so a PXE or self-boot
// install can fetch it) and then observes the install through the install log.
// The node must reach the installer on its own (its saved boot order PXE- or
// media-boots it); the installed OS comes up via the ISO's after-install=reboot
// action. Health is awaited only when an address is resolvable — a truly
// headless node with no reachable health endpoint returns success once the
// installer reports completion.
func (o *Orchestrator) provisionUnmanaged(ctx context.Context, node *DiscoveredNode) error {
	o.logger.Info("bootstrap: provisioning unmanaged node — no board management, no hardware operations; ISO self-boots via after-install=reboot",
		slog.String("hostname", node.Hostname),
		slog.String("boot_method", node.EffectiveBootMethod()))

	// Publish per-MAC config for the install-time fetch (best effort — the
	// node falls back to ISO-baked config if the server is unreachable).
	if err := o.stagePerMACConfig(ctx, node); err != nil {
		o.logger.Warn("bootstrap: unmanaged: per-MAC config staging failed, node will fall back to ISO-baked config",
			slog.String("hostname", node.Hostname),
			slog.String("error", err.Error()))
	}

	installURL, urlErr := installLogBaseURL(&o.config.Deployer)
	if urlErr != nil {
		return urlErr
	}

	// Observe the install via the install log. We cannot (and must not) power
	// or boot the node; we wait for it to install and report completion.
	installStart := time.Now()
	poller := &InstallLogPoller{
		BaseURL:  installURL,
		Hostname: sanitizeHostnameForInstallPath(node.Hostname),
		MACs:     allNodeMACs(node),
		Since:    installStart,
		Interval: defaultInstallLogPollInterval,
		Logger:   o.logger,
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, bootProbeTimeout)
	logResult, lastErr := poller.Wait(probeCtx)
	probeCancel()

	logURL := installURL + "/installs/" + node.Hostname + "/install.log"
	if lastErr != nil || logResult == nil || !logResult.Found {
		return ErrInstallLogNotFound{Hostname: node.Hostname, URL: logURL, Cause: lastErr}
	}
	if !logResult.Success() {
		return ErrInstallFailed{Hostname: node.Hostname, ExitCode: logResult.ExitCode, LogURL: logURL}
	}
	o.logger.Info("bootstrap: unmanaged: installer reported success; node self-boots the installed OS via after-install=reboot",
		slog.String("hostname", node.Hostname),
		slog.Int("exit_code", logResult.ExitCode))

	healthAddrs := candidateHealthAddresses(node, logResult, installURL)
	if len(healthAddrs) == 0 {
		o.logger.Info("bootstrap: unmanaged: no health address resolvable — install complete (headless node, operator-verified)",
			slog.String("hostname", node.Hostname))
		return nil
	}
	return o.awaitPostInstallHealth(ctx, node, healthAddrs, installURL)
}

// bmcBootNode connects to the BMC, sets PXE boot, and reboots the node
// into PXE in a power-state-aware way.
//
// The Supermicro X10 OEM boot override (smc-oem-ipmi) that SetBootDevice
// issues is ONE-SHOT: it is consumed by the NEXT boot. If the node is
// already powered on, a plain PowerOn is a no-op and the override is never
// consumed — the node keeps running its on-disk OS and never PXEs. So after
// setting the boot device we query the current power state and force a full
// power cycle (the most reliable reboot on X10 ATEN firmware) when the node
// is already on; otherwise we power it on from cold. A PowerStatus read
// error is non-fatal: we log a WARN and fall back to a best-effort PowerOn
// rather than aborting the whole provision on a transient status read.
func (o *Orchestrator) bmcBootNode(ctx context.Context, node *DiscoveredNode) error {
	bmcConfig := buildBMCConfig(&node.NodeConfig, o.nodeBMCTLSProvider(&node.NodeConfig))

	client, err := o.bmcFactory.NewClient(bmcConfig)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.SetBootDevice(ctx, bmc.BootDevicePXE, false); err != nil {
		return err
	}

	state, err := client.PowerStatus(ctx)
	if err != nil {
		o.logger.Warn("bootstrap: power status read failed, falling back to power on",
			slog.String("hostname", node.Hostname),
			slog.String("error", err.Error()))
		return client.PowerOn(ctx)
	}
	if state == bmc.PowerStateOn {
		o.logger.Info("bootstrap: node already powered on, power cycling to consume one-shot PXE override",
			slog.String("hostname", node.Hostname),
			slog.String("state", string(state)))
		return client.PowerCycle(ctx)
	}
	o.logger.Info("bootstrap: powering on node for PXE boot",
		slog.String("hostname", node.Hostname),
		slog.String("state", string(state)))
	return client.PowerOn(ctx)
}

// managedPXEProvision runs the FULL PXE provisioning lifecycle for a node WITH
// board management, giving the managed PXE path the same fully-automated
// post-install handling the virtual-media path has (there is no CD to unmount):
//
//  1. Fire the one-shot PXE install boot (bmcBootNode).
//  2. Wait for the installer to report success via the pxeboot install-log
//     (the node PXE-boots, installs to disk, then `poweroff`s at S5).
//  3. Switch the node to persistent disk boot.
//  4. Power the node on from its post-install poweroff (postInstallPowerOn).
//  5. Wait for the installed platformd health endpoint.
//
// Without steps 2-5 a PXE node sat powered off after install and health never
// came up — the automation only fired the install boot and then blindly waited
// for health. This closes that gap symmetrically with bootNodeVirtualMedia.
func (o *Orchestrator) managedPXEProvision(ctx context.Context, node *DiscoveredNode) error {
	bmcConfig := buildBMCConfig(&node.NodeConfig, o.nodeBMCTLSProvider(&node.NodeConfig))

	installURL, urlErr := installLogBaseURL(&o.config.Deployer)
	if urlErr != nil {
		return urlErr
	}

	// Publish per-MAC config for the install-time fetch before the node is
	// booted, exactly as the unmanaged and virtual-media paths do — a
	// managed node's autoinstall reads the same keys (best effort, as
	// there: docs/bootstrap/engineering.md §4, "Deliberately fail-open").
	if err := o.stagePerMACConfig(ctx, node); err != nil {
		o.logger.Warn("bootstrap: pxe: per-MAC config staging failed, node will fall back to ISO-baked config",
			slog.String("hostname", node.Hostname),
			slog.String("error", err.Error()))
	}

	// Fire the PXE install boot.
	installStart := time.Now()
	if err := o.bmcBootNode(ctx, node); err != nil {
		return err
	}

	// Safety net: always leave the node powered on when we return.
	defer o.deferredPowerOn(ctx, bmcConfig, node.Hostname)

	// Wait for the installer to finish (PXE-boot -> install -> poweroff).
	poller := &InstallLogPoller{
		BaseURL:  installURL,
		Hostname: sanitizeHostnameForInstallPath(node.Hostname),
		MACs:     allNodeMACs(node),
		Since:    installStart,
		Interval: defaultInstallLogPollInterval,
		Logger:   o.logger,
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, bootProbeTimeout)
	logResult, lastErr := poller.Wait(probeCtx)
	probeCancel()

	logURL := installURL + "/installs/" + node.Hostname + "/install.log"
	if lastErr != nil || logResult == nil || !logResult.Found {
		return ErrInstallLogNotFound{Hostname: node.Hostname, URL: logURL, Cause: lastErr}
	}
	if !logResult.Success() {
		return ErrInstallFailed{Hostname: node.Hostname, ExitCode: logResult.ExitCode, LogURL: logURL}
	}
	o.logger.Info("bootstrap: pxe: installer reported success",
		slog.String("hostname", node.Hostname),
		slog.Int("exit_code", logResult.ExitCode))

	// Post-install: persistent disk boot, power on from S5, wait for health.
	postClient, postErr := o.bmcFactory.NewClient(bmcConfig)
	if postErr != nil {
		return ErrBMCReconnect{Hostname: node.Hostname, Operation: "pxe post-install", Cause: postErr}
	}
	defer postClient.Close()

	if err := postClient.SetBootDevice(ctx, bmc.BootDeviceDisk, true); err != nil {
		return ErrBootDeviceSetFailed{Hostname: node.Hostname, Device: string(bmc.BootDeviceDisk), Cause: err}
	}
	if err := o.postInstallPowerOn(ctx, postClient, bmcConfig, node.Hostname); err != nil {
		return err
	}

	healthAddrs := candidateHealthAddresses(node, logResult, installURL)
	if len(healthAddrs) == 0 {
		o.logger.Warn("bootstrap: pxe: no usable health addresses after install, skipping health wait",
			slog.String("hostname", node.Hostname))
		return nil
	}
	return o.awaitPostInstallHealth(ctx, node, healthAddrs, installURL)
}

// seedTemplatesWithSeeder creates a seeder and runs it against the first
// control-plane node. It returns the seeder so that subsequent phases
// (bmc-enroll) can retrieve the hostname-to-profile-ID map without making
// additional API calls.
func (o *Orchestrator) seedTemplatesWithSeeder(ctx context.Context) (*Seeder, error) {
	cpNodes := o.nodesByRole(RoleControlPlane)
	if len(cpNodes) == 0 {
		return nil, ErrNoControlPlaneNode{}
	}

	// The seeder uploads over TLS to a control plane whose CA was
	// self-provisioned minutes ago: the pool must be captured and
	// verified before the first upload, and there is no system-pool
	// fallback to try instead. Capture comes before address selection so
	// a registration.json that lands during the capture wait is what the
	// address lookup below sees.
	pool, err := o.ControlPlaneCAPool(ctx)
	if err != nil {
		return nil, ErrCABundleRequired{Operation: "template seeding", Cause: err}
	}
	tlsName, err := o.controlPlaneTLSName()
	if err != nil {
		return nil, err
	}

	// Resolve the control-plane IP from registration.json (uploaded by
	// platformd after first-boot). The hostname alone won't resolve
	// because DNS isn't running yet during bootstrap.
	// Resolution order: (1) platformd-uploaded registration.json (most
	// authoritative — it's the IP platformd ACTUALLY listens on);
	// (2) operator-declared static IP from nodes[].interfaces
	// (reliable when registration.json is missing because first-boot
	// forensic uploader hasn't run yet); (3) hostname (last resort —
	// may DNS-resolve to a stale/wrong address on shared homelab DNS).
	controlHost := cpNodes[0].Hostname
	controlMACs := allNodeMACs(&cpNodes[0])
	resolved := false
	if baseURL, urlErr := installLogBaseURL(&o.config.Deployer); urlErr == nil {
		if regIP, fetchErr := fetchRegistrationIP(baseURL, controlHost, controlMACs); fetchErr == nil && regIP != "" {
			controlHost = regIP
			resolved = true
			o.logger.Info("bootstrap: resolved control-plane IP from registration",
				slog.String("ip", regIP))
		}
	}
	if !resolved {
		if staticIPs := cpNodes[0].StaticIPv4s(); len(staticIPs) > 0 {
			controlHost = staticIPs[0]
			o.logger.Info("bootstrap: resolved control-plane IP from nodes[].interfaces static IP",
				slog.String("ip", controlHost))
		}
	}
	controlAddr := controlHost + ":8443"
	o.logger.Info("bootstrap: seeding templates to control plane",
		slog.String("address", controlAddr))

	seeder := NewSeeder(SeederParams{
		ControlPlaneAddr: controlAddr,
		Config:           o.config,
		Discovered:       o.discovered,
		Logger:           o.logger,
		CPCAPool:         pool,
		ServerName:       tlsName,
		ConfigDir:        o.configDir,
	})
	if err := seeder.Seed(ctx); err != nil {
		return nil, err
	}
	return seeder, nil
}

// hasBMCEnrollNodes reports whether at least one discovered node has
// BMCEnroll set to true.
func (o *Orchestrator) hasBMCEnrollNodes() bool {
	for i := range o.discovered {
		if o.discovered[i].BMCEnroll {
			return true
		}
	}
	return false
}

// runBMCEnroll iterates over all discovered nodes that have BMCEnroll=true
// and calls POST /api/v1/bmc/{profileID}/enroll on the control plane for
// each. Failures are non-fatal: they are logged as warnings and recorded in
// result.BMCEnrollments so the operator can retry with `platformctl bmc enroll`.
//
// The seeder's HTTP client (CA-pool verified when cpCAPool is available,
// otherwise system roots) is reused for enrollment.
func (o *Orchestrator) runBMCEnroll(ctx context.Context, result *BootstrapResult, seeder *Seeder) {
	// Use the seeder's already-resolved control-plane address. The seeder ran
	// the same registration-lookup + static-IP resolution at seed time, so
	// reusing its address avoids duplicate network lookups and keeps the
	// bmc-enroll phase pointed at the same host the seed phase used.
	controlAddr := seeder.controlPlaneAddr
	if controlAddr == "" {
		o.logger.Warn("bootstrap: bmc-enroll: seeder has no control-plane address, skipping")
		return
	}

	o.logger.Info("bootstrap: bmc-enroll: using control-plane address",
		slog.String("address", controlAddr))

	profileIDs := seeder.ProfileIDs()

	// Resolve backup directory once; silently skip backup writing when empty.
	backupsDir, bdErr := o.config.EffectiveBackupsDir()
	if bdErr != nil {
		o.logger.Warn("bootstrap: bmc-enroll: cannot resolve backups_dir, skipping backups",
			slog.String("error", bdErr.Error()))
		backupsDir = ""
	}

	for i := range o.discovered {
		node := &o.discovered[i]
		if !node.BMCEnroll {
			continue
		}

		profileID, ok := profileIDs[node.Hostname]
		if !ok || profileID == 0 {
			o.logger.Warn("bootstrap: bmc-enroll: profile ID not found for node, skipping enrollment",
				slog.String("hostname", node.Hostname))
			result.BMCEnrollments = append(result.BMCEnrollments, BMCEnrollOutcome{
				Hostname:  node.Hostname,
				ProfileID: 0,
				OK:        false,
				Detail:    "profile ID not available (seed phase did not produce an ID)",
			})
			continue
		}

		o.logger.Info("bootstrap: bmc-enroll: enrolling node",
			slog.String("hostname", node.Hostname),
			slog.Uint64("profile_id", profileID))

		enrollResp, enrollErr := o.doEnrollRequest(ctx, seeder.client, controlAddr, profileID)
		outcome := BMCEnrollOutcome{
			Hostname:  node.Hostname,
			ProfileID: profileID,
		}
		if enrollErr != nil {
			o.logger.Warn("bootstrap: bmc-enroll: enrollment failed (non-fatal, re-run platformctl bmc enroll)",
				slog.String("hostname", node.Hostname),
				slog.Uint64("profile_id", profileID),
				slog.String("error", enrollErr.Error()))
			outcome.OK = false
			outcome.Detail = enrollErr.Error()
		} else {
			o.logger.Info("bootstrap: bmc-enroll: enrollment succeeded",
				slog.String("hostname", node.Hostname),
				slog.Uint64("profile_id", profileID))
			outcome.OK = true
			// Write backup artifacts when backups_dir is configured and the
			// response carries factory cert data.
			if backupsDir != "" && enrollResp != nil {
				if writeErr := writeBMCEnrollBackups(backupsDir, node.Hostname, enrollResp); writeErr != nil {
					o.logger.Warn("bootstrap: bmc-enroll: failed to write backup artifacts",
						slog.String("hostname", node.Hostname),
						slog.String("error", writeErr.Error()))
				}
			}
		}
		result.BMCEnrollments = append(result.BMCEnrollments, outcome)
	}
}

// enrollResponse is a minimal decode target for the BMC enrollment REST
// response. It captures the fields needed for backup writing; unknown fields
// are discarded.
type enrollResponse struct {
	DeviceID        uint64          `json:"device_id,string"`
	FactoryCertPEM  string          `json:"factory_cert_pem,omitempty"`
	FactoryCertMeta json.RawMessage `json:"factory_cert_meta,omitempty"`
}

// doEnrollRequest posts to POST /api/v1/bmc/{profileID}/enroll on the
// control plane using the seeder's HTTP client (same TLS trust as seed phase).
// An empty JSON object is sent as the request body so profile defaults drive
// the ceremony.
func (o *Orchestrator) doEnrollRequest(ctx context.Context, client *http.Client, controlAddr string, profileID uint64) (*enrollResponse, error) {
	url := fmt.Sprintf("https://"+controlAddr+bmcEnrollPath, profileID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strconv.Itoa(resp.StatusCode)
		if len(body) > 0 {
			detail = fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil, ErrBMCEnrollFailed{Cause: &MessageError{Msg: detail}}
	}

	if readErr != nil {
		return nil, readErr
	}

	// Unwrap the standard REST envelope: {code, success, payload}.
	var envelope struct {
		Payload enrollResponse `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		// Fall back to direct response shape.
		var direct enrollResponse
		if jsonErr := json.Unmarshal(body, &direct); jsonErr != nil {
			return nil, jsonErr
		}
		return &direct, nil
	}
	return &envelope.Payload, nil
}

// writeBMCEnrollBackups writes enrollment artifacts to the backup directory:
//
//   - <backupsDir>/<hostname>/bmc/factory-cert.pem (0600) — factory cert PEM
//   - <backupsDir>/<hostname>/bmc/factory-cert.json (0600) — factory cert metadata
//   - <backupsDir>/<hostname>/bmc/enrollment.json (0600)  — full response JSON
//
// Directories are created with 0700. Missing/empty fields are silently skipped.
func writeBMCEnrollBackups(backupsDir, hostname string, resp *enrollResponse) error {
	if resp == nil {
		return nil
	}
	dir := filepath.Join(backupsDir, hostname, "bmc")
	if err := os.MkdirAll(dir, bmcBackupDirMode); err != nil {
		return err
	}
	if resp.FactoryCertPEM != "" {
		path := filepath.Join(dir, "factory-cert.pem")
		if err := os.WriteFile(path, []byte(resp.FactoryCertPEM), bmcBackupFileMode); err != nil {
			return err
		}
	}
	if len(resp.FactoryCertMeta) > 0 {
		path := filepath.Join(dir, "factory-cert.json")
		if err := os.WriteFile(path, resp.FactoryCertMeta, bmcBackupFileMode); err != nil {
			return err
		}
	}
	// Serialize full enrollment response.
	fullJSON, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "enrollment.json"), fullJSON, bmcBackupFileMode)
}

// controlPlaneHealthGate verifies that every control-plane node is healthy
// before the bootstrap container is torn down. This prevents tearing down
// DHCP/DNS services before the control-plane is ready to take over.
//
// Each control-plane node is polled concurrently. The gate succeeds only when
// ALL nodes pass their health check within the timeout. On failure the caller
// should skip teardown and log the error.
func (o *Orchestrator) controlPlaneHealthGate(ctx context.Context) error {
	cpNodes := o.nodesByRole(RoleControlPlane)
	if len(cpNodes) == 0 {
		return ErrNoControlPlaneNode{}
	}

	timeout := defaultControlPlaneHealthGateTimeout

	o.logger.Info("bootstrap: running control-plane health gate before teardown",
		slog.Int("control_plane_nodes", len(cpNodes)),
		slog.Duration("timeout", timeout))

	// The gate probes the same DNS-only control-plane certificates the
	// post-install wait did, so it verifies them for the same name.
	serverName := ""
	if o.ownsHealthCheckerTrust() {
		tlsName, err := o.controlPlaneTLSName()
		if err != nil {
			return ErrControlPlaneHealthGateFailed{Timeout: timeout, Cause: err}
		}
		serverName = tlsName
	}

	gateCtx, gateCancel := context.WithTimeout(ctx, timeout)
	defer gateCancel()

	// Poll all control-plane nodes concurrently.
	type nodeHealth struct {
		hostname string
		err      error
	}

	resultCh := make(chan nodeHealth, len(cpNodes))
	var wg sync.WaitGroup

	for i := range cpNodes {
		node := &cpNodes[i]
		wg.Add(1)
		go func(n *DiscoveredNode) {
			defer wg.Done()
			// Dial wherever the node is reachable — registration IP,
			// static IPv4, hostname — the same candidates every other
			// control-plane client uses; the name verified is the same
			// too.
			err := o.waitForHealthAny(gateCtx, o.controlPlaneDialCandidates(n), "", n.Hostname, allNodeMACs(n), serverName)
			resultCh <- nodeHealth{hostname: n.Hostname, err: err}
		}(node)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var firstErr error
	for nh := range resultCh {
		if nh.err != nil {
			o.logger.Warn("bootstrap: control-plane node failed health gate",
				slog.String("hostname", nh.hostname),
				slog.String("error", nh.err.Error()))
			if firstErr == nil {
				firstErr = nh.err
			}
		} else {
			o.logger.Info("bootstrap: control-plane node passed health gate",
				slog.String("hostname", nh.hostname))
		}
	}

	if firstErr != nil {
		return ErrControlPlaneHealthGateFailed{
			Timeout: timeout,
			Cause:   firstErr,
		}
	}

	o.logger.Info("bootstrap: all control-plane nodes passed health gate")
	return nil
}

// teardownContainer tears down the bootstrap container.
func (o *Orchestrator) teardownContainer(ctx context.Context) error {
	o.logger.Info("bootstrap: tearing down bootstrap container")
	if err := o.deployer.Teardown(ctx); err != nil {
		return ErrContainerTeardownFailed{
			Host:  o.config.Deployer.Host,
			Cause: err,
		}
	}
	return nil
}

// propagateCAPool updates the health checker's TLS root CA pool once the
// control-plane CA bundle has been fetched and stored in o.cpCAPool. This
// is a no-op when the health checker was injected externally (not an
// *httpHealthChecker) or when o.cpCAPool is nil.
func (o *Orchestrator) propagateCAPool() {
	pool := o.cachedControlPlaneCAPool()
	if pool == nil {
		return
	}
	if hc, ok := o.healthChk.(*httpHealthChecker); ok {
		hc.WithCAPool(pool)
	}
}

// newPollTicker is the production pollTicker: a real time.Ticker.
func newPollTicker(interval time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(interval)
	return t.C, t.Stop
}

// cachedControlPlaneCAPool returns the captured control-plane CA pool, or
// nil when no bundle has been verified yet.
func (o *Orchestrator) cachedControlPlaneCAPool() *x509.CertPool {
	o.cpCAMu.Lock()
	defer o.cpCAMu.Unlock()
	return o.cpCAPool
}

// storeControlPlaneCAPool records a pool that passed capture-then-verify.
func (o *Orchestrator) storeControlPlaneCAPool(pool *x509.CertPool) {
	o.cpCAMu.Lock()
	defer o.cpCAMu.Unlock()
	o.cpCAPool = pool
}

// acquireCAFetchGate takes the capture gate or returns ctx.Err() if the
// context ends first. The returned release must be called once the
// attempt is over.
func (o *Orchestrator) acquireCAFetchGate(ctx context.Context) (release func(), err error) {
	o.cpCAFetchGateOnce.Do(func() { o.cpCAFetchGate = make(chan struct{}, 1) })
	select {
	case o.cpCAFetchGate <- struct{}{}:
		return func() { <-o.cpCAFetchGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// captureControlPlaneCAPoolOnce performs one serialized capture attempt:
// holding the capture gate it returns immediately when another waiter has
// already stored the pool, otherwise it runs fetchControlPlaneCABundle.
// Either way the pool is propagated to the health checker on success.
func (o *Orchestrator) captureControlPlaneCAPoolOnce(ctx context.Context) error {
	release, err := o.acquireCAFetchGate(ctx)
	if err != nil {
		return err
	}
	defer release()
	if o.cachedControlPlaneCAPool() != nil {
		o.propagateCAPool()
		return nil
	}
	_, err = o.fetchControlPlaneCABundle(ctx)
	return err
}

// newTicker builds a poll ticker through pollTicker, defaulting to a
// real time.Ticker.
func (o *Orchestrator) newTicker(interval time.Duration) (<-chan time.Time, func()) {
	if o.pollTicker != nil {
		return o.pollTicker(interval)
	}
	return newPollTicker(interval)
}

// awaitPostInstallHealth is the post-install health wait shared by the
// PXE, virtual-media and unmanaged paths. It runs under
// defaultPostInstallHealthTimeout and, when the built-in checker owns
// probe trust, verifies every role against the platform anchor: it
// captures the control plane's CA bundle first so the probe has the
// anchor, and probes with the name the node's certificate carries — the
// control plane's public webservice name, or a gateway's or worker's
// platform-listener name from its role template — so a DNS-only leaf
// verifies while the node is dialed by address.
//
// The ordering is the whole point (#107): a control plane self-provisions
// its CA seconds before it starts serving, so probing before the bundle is
// captured verifies its leaf against the system pool and fails for the
// entire window, however healthy the node is. Every other node's platform
// listener serves a leaf the control plane issued (device-attest-01), so
// the same bundle, already cached by then, verifies it (#655).
func (o *Orchestrator) awaitPostInstallHealth(ctx context.Context, node *DiscoveredNode, healthAddrs []string, installURL string) error {
	healthCtx, healthCancel := context.WithTimeout(ctx, o.config.EffectivePostInstallHealthTimeout())
	defer healthCancel()
	joined := strings.Join(healthAddrs, ",")
	serverName := ""
	if o.ownsHealthCheckerTrust() {
		tlsName, err := o.postInstallTLSName(node)
		if err != nil {
			return ErrHealthCheckFailed{Address: joined, Cause: err}
		}
		if err := o.awaitControlPlaneCAPool(healthCtx, node.Hostname); err != nil {
			return ErrHealthCheckFailed{Address: joined, Cause: err}
		}
		serverName = tlsName
	}
	if err := o.waitForHealthAny(healthCtx, healthAddrs, installURL, node.Hostname, allNodeMACs(node), serverName); err != nil {
		return ErrHealthCheckFailed{Address: joined, Cause: err}
	}
	return nil
}

// ownsHealthCheckerTrust reports whether the orchestrator built the health
// checker itself and therefore supplies its TLS trust anchor via
// propagateCAPool. An injected HealthChecker owns its own trust, so there
// is nothing to capture on its behalf.
func (o *Orchestrator) ownsHealthCheckerTrust() bool {
	_, ok := o.healthChk.(*httpHealthChecker)
	return ok
}

// awaitControlPlaneCAPool captures and verifies the control-plane CA
// bundle (fetchControlPlaneCABundle, which also propagates the pool to
// the health checker) and retries on the health cadence until it
// succeeds or ctx ends. A connection refused or an HTTP error while the
// node is still booting means "not up yet", so it is retried; a bundle
// the served chain does not verify against, or a configuration fact that
// waiting cannot change, fails immediately with its own error. When the
// bundle was already captured — for an earlier node, or by a concurrent
// waiter — the cached pool is propagated and no fetch is made.
func (o *Orchestrator) awaitControlPlaneCAPool(ctx context.Context, hostname string) error {
	// The first attempt is immediate; the ticker is built only once an
	// attempt has failed, so a serving control plane never waits an
	// interval.
	var tick <-chan time.Time
	stop := func() {}
	defer func() { stop() }()
	attempts := 0
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return CABundleUnavailableError{Hostname: hostname, Attempts: attempts, Cause: err, LastErr: lastErr}
		}
		attempts++
		err := o.captureControlPlaneCAPoolOnce(ctx)
		if err == nil {
			o.logger.Info("bootstrap: control-plane CA bundle captured and verified; health probes now verify against it",
				slog.String("hostname", hostname),
				slog.Int("attempts", attempts))
			return nil
		}
		if isTerminalCABundleError(err) {
			return err
		}
		lastErr = err
		o.logger.Debug("bootstrap: control-plane CA bundle not yet available, retrying",
			slog.String("hostname", hostname),
			slog.Int("attempt", attempts),
			slog.String("error", err.Error()))
		if tick == nil {
			tick, stop = o.newTicker(defaultHealthInterval)
		}
		select {
		case <-ctx.Done():
			return CABundleUnavailableError{Hostname: hostname, Attempts: attempts, Cause: ctx.Err(), LastErr: lastErr}
		case <-tick:
		}
	}
}

// isTerminalCABundleError reports whether a fetchControlPlaneCABundle
// failure cannot be cured by waiting for the node to finish booting: a
// bundle that fails capture-then-verify, a bundle with no certificates,
// or a control plane the orchestrator has no address or TLS name for.
func isTerminalCABundleError(err error) bool {
	var verifyErr ErrCABundleVerifyFailed
	var invalidErr ErrCABundleInvalid
	var noCP ErrNoControlPlaneNode
	var noAddr ControlPlaneStaticIPRequiredError
	var noName ControlPlaneTLSNameUnknownError
	return errors.As(err, &verifyErr) ||
		errors.As(err, &invalidErr) ||
		errors.As(err, &noCP) ||
		errors.As(err, &noAddr) ||
		errors.As(err, &noName)
}

// healthProbe returns the probe a health wait uses. With a serverName the
// probed certificate is verified for that DNS name rather than the dialed
// address, when the checker implements ServerNameHealthChecker; an
// injected checker that does not is probed as-is.
func (o *Orchestrator) healthProbe(serverName string) func(ctx context.Context, address string) error {
	if serverName != "" {
		if named, ok := o.healthChk.(ServerNameHealthChecker); ok {
			return func(ctx context.Context, address string) error {
				return named.CheckServerName(ctx, address, serverName)
			}
		}
	}
	return o.healthChk.Check
}

// waitForHealth polls a node's health endpoint until healthy or context expires.
// The first probe is immediate so an already-healthy node does not wait a
// whole interval; subsequent probes follow the ticker. Cancellation wins
// over the probe: a context that is already done never reports healthy.
// serverName, when non-empty, is the DNS name the probed certificate must
// be issued for (see healthProbe).
func (o *Orchestrator) waitForHealth(ctx context.Context, address, serverName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	probe := o.healthProbe(serverName)
	if err := probe(ctx, address); err == nil {
		return nil
	}

	tick, stop := o.newTicker(defaultHealthInterval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick:
			if err := probe(ctx, address); err == nil {
				return nil
			}
		}
	}
}

// nodesByRole returns discovered nodes matching the given role.
func (o *Orchestrator) nodesByRole(role string) []DiscoveredNode {
	nodes := make([]DiscoveredNode, 0)
	for i := range o.discovered {
		if o.discovered[i].Role == role {
			nodes = append(nodes, o.discovered[i])
		}
	}
	return nodes
}

// populateNodeResults fills the result with initial discovered status for all nodes.
func (o *Orchestrator) populateNodeResults(result *BootstrapResult) {
	result.Nodes = make([]NodeResult, len(o.discovered))
	for i := range o.discovered {
		result.Nodes[i] = NodeResult{
			Hostname:   o.discovered[i].Hostname,
			Role:       o.discovered[i].Role,
			MACs:       append([]string(nil), o.discovered[i].DiscoveredMACs...),
			BMCManaged: o.discovered[i].BMCManaged,
			Status:     nodeStatusDiscovered,
		}
	}
}

// updateNodeStatus updates a node's status in the result.
func (o *Orchestrator) updateNodeStatus(result *BootstrapResult, hostname, status, errMsg string) {
	for i := range result.Nodes {
		if result.Nodes[i].Hostname == hostname {
			result.Nodes[i].Status = status
			result.Nodes[i].Error = errMsg
			return
		}
	}
}

// toDiscoveredNodeInfos converts DiscoveredNode slice to container.DiscoveredNodeInfo slice.
func toDiscoveredNodeInfos(nodes []DiscoveredNode) []container.DiscoveredNodeInfo {
	infos := make([]container.DiscoveredNodeInfo, len(nodes))
	for i := range nodes {
		infos[i] = container.DiscoveredNodeInfo{
			MACs:         append([]string(nil), nodes[i].DiscoveredMACs...),
			Role:         nodes[i].Role,
			Hostname:     nodes[i].Hostname,
			Architecture: nodes[i].IPXEArchitecture(),
			MediaSet:     nodes[i].MediaSet(),
			BootModel:    nodes[i].EffectiveBootModel(),
		}
	}
	return infos
}

// httpHealthChecker implements HealthChecker by consulting the node's
// registration.json that platformd POSTs to the pxeboot server on
// successful startup, with an HTTPS /api/v1/status fallback.
//
// The registration.json path is authoritative: the node self-reports
// `{"services":{"platformd":"running","sshd":"running"}}` after it has
// fully booted and all services are listening. Polling that artifact
// avoids having to guess the correct webservice port (CP uses 8443,
// gateway uses 443/9443) and avoids the need for InsecureSkipVerify
// against a not-yet-trusted CA.
type httpHealthChecker struct {
	// client probes without an expected server name; namedClients hold
	// one client per expected server name, built from caPool on demand.
	// All three are guarded by mu and rebuilt together by WithCAPool.
	client       *http.Client
	namedClients map[string]*http.Client
	caPool       *x509.CertPool
	logger       *slog.Logger
	pxebootURL   string
	httpsPorts   []int
	mu           sync.Mutex
}

// newHTTPHealthChecker creates a health checker that first probes the
// pxeboot-hosted registration.json (plain HTTP, known-trusted) and
// falls back to HTTPS /api/v1/status across the candidate platformd
// ports. When caPool is non-nil it is used to verify the server's TLS
// certificate; when nil the system certificate pool is used.
func newHTTPHealthChecker(logger *slog.Logger, caPool *x509.CertPool) *httpHealthChecker {
	// Force the pure-Go DNS resolver to avoid SIGFPE in CGO's getaddrinfo
	// when running as a statically linked binary with glibc.
	return &httpHealthChecker{
		client:     newHealthHTTPClient(caPool, ""),
		caPool:     caPool,
		logger:     logger,
		httpsPorts: []int{8443, 9443, 443},
	}
}

// newHealthHTTPClient builds a probe client. caPool nil means the system
// pool; serverName, when set, is the DNS name the server's certificate
// must be issued for regardless of the address dialed.
func newHealthHTTPClient(caPool *x509.CertPool, serverName string) *http.Client {
	// Force the pure-Go DNS resolver to avoid SIGFPE in CGO's getaddrinfo
	// when running as a statically linked binary with glibc.
	goResolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{
		Timeout:  5 * time.Second,
		Resolver: goResolver,
	}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caPool,
				ServerName: serverName,
			},
		},
	}
}

// WithCAPool replaces the checker's HTTP clients with ones whose TLS root
// CA pool is the given pool. This is called once the control-plane CA
// bundle has been fetched so subsequent health probes verify the server
// certificate rather than relying on the system pool. Clients are
// swapped whole rather than reconfigured in place: an http.Transport
// must not be mutated while a concurrent Check is using it.
func (h *httpHealthChecker) WithCAPool(pool *x509.CertPool) {
	if pool == nil {
		return
	}
	h.mu.Lock()
	previous := h.client
	previousNamed := h.namedClients
	h.caPool = pool
	h.client = newHealthHTTPClient(pool, "")
	h.namedClients = nil
	h.mu.Unlock()
	previous.CloseIdleConnections()
	for _, c := range previousNamed {
		c.CloseIdleConnections()
	}
}

// probeClient returns the client a probe should use for the given
// expected server name ("" for none), taken under the lock so a
// concurrent WithCAPool swap is either fully seen or not at all. Named
// clients are built from the current pool on first use.
func (h *httpHealthChecker) probeClient(serverName string) *http.Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	if serverName == "" {
		return h.client
	}
	if c, ok := h.namedClients[serverName]; ok {
		return c
	}
	if h.namedClients == nil {
		h.namedClients = make(map[string]*http.Client)
	}
	c := newHealthHTTPClient(h.caPool, serverName)
	h.namedClients[serverName] = c
	return c
}

// WithPxebootURL sets the base URL for the pxeboot server so the
// registration-json probe can be constructed. Safe to call before Check.
func (h *httpHealthChecker) WithPxebootURL(u string) {
	h.pxebootURL = strings.TrimSuffix(u, "/")
}

// regStatus is the minimal shape of registration.json that the firstboot
// forensic-upload script writes to pxeboot.
type regStatus struct {
	Hostname  string            `json:"hostname"`
	IP        string            `json:"ip"`
	Timestamp time.Time         `json:"timestamp"`
	Services  map[string]string `json:"services"`
}

// Check reports the node healthy only when an HTTPS probe on the
// platformd API returns 200. registration.json (pxeboot) supplies the
// target IP when the hostname wouldn't resolve, but it is never
// authoritative on its own — the file is written by the forensic
// uploader early in firstboot, BEFORE platformd reaches listening
// state, so trusting it would let health return true while :8443 is
// still down and subsequent seed/gRPC calls fail with "connection
// refused".
func (h *httpHealthChecker) Check(ctx context.Context, address string) error {
	return h.CheckServerName(ctx, address, "")
}

// CheckServerName is Check with the server's certificate verified against
// serverName instead of the dialed address, for endpoints whose
// certificate names only their DNS identity.
func (h *httpHealthChecker) CheckServerName(ctx context.Context, address, serverName string) error {
	client := h.probeClient(serverName)
	probeAddr := address
	if h.pxebootURL != "" {
		hostname := address
		if i := strings.Index(hostname, "."); i >= 0 {
			hostname = hostname[:i]
		}
		url := h.pxebootURL + "/installs/" + hostname + "/registration.json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			resp, rerr := client.Do(req)
			if rerr == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var reg regStatus
					if derr := json.NewDecoder(resp.Body).Decode(&reg); derr == nil && reg.IP != "" {
						probeAddr = reg.IP
					}
				}
			}
		}
	}

	var lastErr error
	for _, port := range h.httpsPorts {
		url := fmt.Sprintf("https://%s:%d/api/v1/status", probeAddr, port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = probeFailure(lastErr, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = &MessageError{Msg: fmt.Sprintf("GET %s returned HTTP %d", url, resp.StatusCode)}
	}
	if lastErr != nil {
		return ErrHealthCheckFailed{Address: probeAddr, Cause: lastErr}
	}
	return ErrHealthCheckFailed{Address: probeAddr}
}

// probeFailure keeps the more telling of two port failures. A port that
// answered — and then failed TLS verification or returned a bad status —
// says more about the node than a port that refused the dial, so a dial
// failure never replaces it.
func probeFailure(kept, next error) error {
	if kept != nil && !isDialError(kept) && isDialError(next) {
		return kept
	}
	return next
}

// isDialError reports whether err is a failure to open the connection.
func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
