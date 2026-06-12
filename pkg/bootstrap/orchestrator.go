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

	// defaultHealthTimeout is the default timeout for waiting on node health.
	defaultHealthTimeout = 10 * time.Minute

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
type HealthChecker interface {
	// Check returns nil when the node at the given address is healthy.
	Check(ctx context.Context, address string) error
}

// OrchestratorParams holds the dependencies for creating an Orchestrator.
type OrchestratorParams struct {
	Config        *BootstrapConfig
	ConfigPath    string // Path to the bootstrap YAML file, used to resolve relative template paths.
	BMCFactory    bmc.ClientFactory
	Logger        *slog.Logger
	Deployer      Deployer
	HealthChecker HealthChecker
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
	config         *BootstrapConfig
	configDir      string // Directory containing the bootstrap YAML, for resolving relative paths.
	discovered     []DiscoveredNode
	logger         *slog.Logger
	bmcFactory     bmc.ClientFactory
	deployer       Deployer
	healthChk      HealthChecker
	bmcTLSProvider bmc.TLSProvider // run-scoped TLS provider for BMC connections; nil ⇒ system roots

	// cpCAPool is populated after the control-plane CA bundle is successfully
	// fetched via fetchControlPlaneCABundle (capture-then-verify). Once set,
	// the seeder and health checker verify the CP's TLS certificate against
	// this pool rather than relying on the system pool.
	cpCAPool *x509.CertPool

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
		bmcTLSProvider:        bmcTLSProv,
		SkipVirtualMediaMount: params.SkipVirtualMediaMount,
	}, nil
}

// Run executes the complete bootstrap flow and returns the aggregate result.
func (o *Orchestrator) Run(ctx context.Context) (*BootstrapResult, error) {
	result := &BootstrapResult{}
	start := time.Now()

	// Phase 0: Discovery.
	result.Phase = phaseDiscovery
	discovered, err := o.discover(ctx)
	if err != nil {
		result.Duration = time.Since(start)
		return result, ErrBootstrapFailed{Phase: phaseDiscovery, Cause: err}
	}
	o.discovered = discovered
	o.populateNodeResults(result)

	// Phase 1: Switch configuration (optional).
	if o.config.Switch != nil {
		result.Phase = phaseSwitch
		if err := o.configureSwitch(ctx); err != nil {
			result.Duration = time.Since(start)
			return result, ErrBootstrapFailed{Phase: phaseSwitch, Cause: err}
		}
		result.SwitchConfigured = true
	}

	// Phase 2: Deploy bootstrap container.
	if o.deployer != nil {
		result.Phase = phaseDeploy
		if err := o.deployContainer(ctx); err != nil {
			result.Duration = time.Since(start)
			return result, ErrBootstrapFailed{Phase: phaseDeploy, Cause: err}
		}
		result.ContainerDeployed = true
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
	return DiscoverNodes(ctx, o.config.Nodes, o.logger, DiscoveryOptions{
		TLSProvider: o.bmcTLSProvider,
	})
}

// configureSwitch creates a switch configurator and applies configuration.
func (o *Orchestrator) configureSwitch(ctx context.Context) error {
	o.logger.Info("bootstrap: configuring switch",
		slog.String("vendor", o.config.Switch.Vendor))

	swConfig := buildSwitchConfig(o.config.Switch)
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

	errCh := make(chan error, len(cpNodes))
	var wg sync.WaitGroup

	for i := range cpNodes {
		node := &cpNodes[i]
		wg.Add(1)
		go func(n *DiscoveredNode) {
			defer wg.Done()
			errCh <- o.provisionNode(ctx, n, result)
		}(node)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
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

	errCh := make(chan error, len(remaining))
	var wg sync.WaitGroup

	for i := range remaining {
		node := &remaining[i]
		wg.Add(1)
		go func(n *DiscoveredNode) {
			defer wg.Done()
			errCh <- o.provisionNode(ctx, n, result)
		}(node)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
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

	switch node.EffectiveBootMethod() {
	case BootMethodVirtualMedia:
		// Virtual-media boot owns the entire flow including health wait
		// because it has its own cleanup (unmount) responsibilities.
		if err := o.bootNodeVirtualMedia(ctx, node); err != nil {
			o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, err.Error())
			return ErrNodeProvisionFailed{
				Hostname: node.Hostname,
				Role:     node.Role,
				Cause:    err,
			}
		}
		o.updateNodeStatus(result, node.Hostname, nodeStatusInstalled, "")
		return nil
	case BootMethodPXE:
		// fall through to PXE flow below
	default:
		// Caught by config Validate(), but defend in depth.
		err := ErrInvalidBootMethod{Hostname: node.Hostname, Value: node.BootMethod}
		o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, err.Error())
		return ErrNodeProvisionFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

	if node.BMCManaged {
		if err := o.bmcBootNode(ctx, node); err != nil {
			o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, err.Error())
			return ErrNodeProvisionFailed{
				Hostname: node.Hostname,
				Role:     node.Role,
				Cause:    err,
			}
		}
	} else {
		o.logger.Info("bootstrap: manual node requires admin PXE boot",
			slog.String("hostname", node.Hostname),
			slog.Any("macs", node.DiscoveredMACs))
	}

	// Wait for health endpoint.
	healthCtx, healthCancel := context.WithTimeout(ctx, defaultHealthTimeout)
	defer healthCancel()

	address := node.Hostname
	if err := o.waitForHealth(healthCtx, address); err != nil {
		o.updateNodeStatus(result, node.Hostname, nodeStatusFailed, err.Error())
		return ErrNodeProvisionFailed{
			Hostname: node.Hostname,
			Role:     node.Role,
			Cause:    ErrHealthCheckFailed{Address: address, Cause: err},
		}
	}

	o.updateNodeStatus(result, node.Hostname, nodeStatusInstalled, "")
	return nil
}

// bmcBootNode connects to the BMC, sets PXE boot, and powers on.
func (o *Orchestrator) bmcBootNode(ctx context.Context, node *DiscoveredNode) error {
	bmcConfig := buildBMCConfig(&node.NodeConfig, o.bmcTLSProvider)

	client, err := o.bmcFactory.NewClient(bmcConfig)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.SetBootDevice(ctx, bmc.BootDevicePXE, false); err != nil {
		return err
	}

	return client.PowerOn(ctx)
}

// seedTemplates creates a seeder, runs it against the first control-plane
// node, and returns an error. This is a convenience wrapper over
// seedTemplatesWithSeeder for callers that don't need the seeder back.
func (o *Orchestrator) seedTemplates(ctx context.Context) error {
	_, err := o.seedTemplatesWithSeeder(ctx)
	return err
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

	// Resolve the control-plane IP from registration.json (uploaded by
	// platformd after first-boot). The hostname alone won't resolve
	// because DNS isn't running yet during bootstrap.
	// Resolution order: (1) platformd-uploaded registration.json (most
	// authoritative — it's the IP platformd ACTUALLY listens on);
	// (2) operator-declared static IP from overrides.network.interfaces
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
		if staticIPs := staticIPsFromOverrides(cpNodes[0].Overrides); len(staticIPs) > 0 {
			controlHost = staticIPs[0]
			o.logger.Info("bootstrap: resolved control-plane IP from overrides static IP",
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
		CPCAPool:         o.cpCAPool,
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
		return nil, ErrBMCEnrollFailed{Cause: fmt.Errorf("%s", detail)}
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
			err := o.waitForHealth(gateCtx, n.Hostname)
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
	if o.cpCAPool == nil {
		return
	}
	if hc, ok := o.healthChk.(*httpHealthChecker); ok {
		hc.WithCAPool(o.cpCAPool)
	}
}

// waitForHealth polls a node's health endpoint until healthy or context expires.
func (o *Orchestrator) waitForHealth(ctx context.Context, address string) error {
	ticker := time.NewTicker(defaultHealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := o.healthChk.Check(ctx, address); err == nil {
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
			MACs:     append([]string(nil), nodes[i].DiscoveredMACs...),
			Role:     nodes[i].Role,
			Hostname: nodes[i].Hostname,
		}
	}
	return infos
}

// buildSwitchConfig converts the bootstrap SwitchConfig to a switchmgmt.Config.
func buildSwitchConfig(sc *SwitchConfig) *switchmgmt.Config {
	vlans := make([]switchmgmt.VLANConfig, 0, len(sc.VLANs))
	for name, def := range sc.VLANs {
		vlans = append(vlans, switchmgmt.VLANConfig{
			ID:     def.VLAN,
			Name:   name,
			Subnet: def.Subnet,
		})
	}

	ports := make([]switchmgmt.PortConfig, 0, len(sc.PortAssignments))
	for i := range sc.PortAssignments {
		pa := &sc.PortAssignments[i]
		ports = append(ports, switchmgmt.PortConfig{
			Port:        pa.Port,
			Mode:        pa.Mode,
			VLANs:       pa.VLANs,
			Description: pa.Description,
		})
	}

	return &switchmgmt.Config{
		Vendor: switchmgmt.SwitchVendor(sc.Vendor),
		Host:   sc.Host,
		User:   sc.User,
		SSHKey: sc.SSHKey,
		VLANs:  vlans,
		Ports:  ports,
	}
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
	client     *http.Client
	logger     *slog.Logger
	pxebootURL string
	httpsPorts []int
	mu         sync.Mutex
}

// newHTTPHealthChecker creates a health checker that first probes the
// pxeboot-hosted registration.json (plain HTTP, known-trusted) and
// falls back to HTTPS /api/v1/status across the candidate platformd
// ports. When caPool is non-nil it is used to verify the server's TLS
// certificate; when nil the system certificate pool is used.
func newHTTPHealthChecker(logger *slog.Logger, caPool *x509.CertPool) *httpHealthChecker {
	// Force the pure-Go DNS resolver to avoid SIGFPE in CGO's getaddrinfo
	// when running as a statically linked binary with glibc.
	goResolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{
		Timeout:  5 * time.Second,
		Resolver: goResolver,
	}
	return &httpHealthChecker{
		client: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
					RootCAs:    caPool, // nil → system pool
				},
			},
		},
		logger:     logger,
		httpsPorts: []int{8443, 9443, 443},
	}
}

// WithCAPool replaces the HTTP client's TLS root CA pool on the checker.
// This is called once the control-plane CA bundle has been fetched so
// subsequent health probes verify the server certificate rather than
// relying on the system pool.
func (h *httpHealthChecker) WithCAPool(pool *x509.CertPool) {
	if pool == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.client.Transport.(*http.Transport); ok {
		cfg := t.TLSClientConfig.Clone()
		cfg.RootCAs = pool
		t.TLSClientConfig = cfg
	}
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
	probeAddr := address
	if h.pxebootURL != "" {
		hostname := address
		if i := strings.Index(hostname, "."); i >= 0 {
			hostname = hostname[:i]
		}
		url := h.pxebootURL + "/installs/" + hostname + "/registration.json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			resp, rerr := h.client.Do(req)
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
		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	if lastErr != nil {
		return ErrHealthCheckFailed{Address: probeAddr, Cause: lastErr}
	}
	return ErrHealthCheckFailed{Address: probeAddr}
}
