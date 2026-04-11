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
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/switch"
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
)

// BootstrapResult holds the outcome of a complete bootstrap run.
type BootstrapResult struct {
	Phase             string        `json:"phase" yaml:"phase"`
	Nodes             []NodeResult  `json:"nodes" yaml:"nodes"`
	SwitchConfigured  bool          `json:"switch_configured" yaml:"switch_configured"`
	ContainerDeployed bool          `json:"container_deployed" yaml:"container_deployed"`
	ContainerTornDown bool          `json:"container_torn_down" yaml:"container_torn_down"`
	ControlPlaneReady bool          `json:"control_plane_ready" yaml:"control_plane_ready"`
	GatewaysReady     bool          `json:"gateways_ready" yaml:"gateways_ready"`
	WorkersReady      bool          `json:"workers_ready" yaml:"workers_ready"`
	Duration          time.Duration `json:"duration" yaml:"duration"`
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
	// SkipVirtualMediaMount mirrors Orchestrator.SkipVirtualMediaMount.
	SkipVirtualMediaMount bool
}

// Orchestrator runs the complete network bootstrap flow.
type Orchestrator struct {
	config     *BootstrapConfig
	configDir  string // Directory containing the bootstrap YAML, for resolving relative paths.
	discovered []DiscoveredNode
	logger     *slog.Logger
	bmcFactory bmc.ClientFactory
	deployer   Deployer
	healthChk  HealthChecker

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
		healthChk = newHTTPHealthChecker(logger)
	}
	configDir := ""
	if params.ConfigPath != "" {
		configDir = filepath.Dir(params.ConfigPath)
	}
	return &Orchestrator{
		config:                params.Config,
		configDir:             configDir,
		logger:                logger,
		bmcFactory:            params.BMCFactory,
		deployer:              params.Deployer,
		healthChk:             healthChk,
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
	if err := o.seedTemplates(ctx); err != nil {
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

	// Phase 6: Auto-teardown bootstrap container (non-fatal).
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
	return DiscoverNodes(ctx, o.config.Nodes, o.logger)
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
	bmcConfig := buildBMCConfig(&node.NodeConfig)

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

// seedTemplates creates a seeder and runs it against the first control-plane node.
func (o *Orchestrator) seedTemplates(ctx context.Context) error {
	cpNodes := o.nodesByRole(RoleControlPlane)
	if len(cpNodes) == 0 {
		return ErrNoControlPlaneNode{}
	}

	// Resolve the control-plane IP from registration.json (uploaded by
	// platformd after first-boot). The hostname alone won't resolve
	// because DNS isn't running yet during bootstrap.
	controlHost := cpNodes[0].Hostname
	if baseURL, urlErr := installLogBaseURL(&o.config.Deployer); urlErr == nil {
		if regIP, fetchErr := fetchRegistrationIP(baseURL, controlHost); fetchErr == nil && regIP != "" {
			controlHost = regIP
			o.logger.Info("bootstrap: resolved control-plane IP from registration",
				slog.String("ip", regIP))
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
	})
	return seeder.Seed(ctx)
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
			address := n.Hostname
			err := o.waitForHealth(gateCtx, address)
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
				firstErr = ErrHealthCheckFailed{
					Address: nh.hostname,
					Cause:   nh.err,
				}
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

// httpHealthChecker implements HealthChecker using HTTP GET against the REST health endpoint.
type httpHealthChecker struct {
	client *http.Client
	logger *slog.Logger
}

// newHTTPHealthChecker creates a health checker that uses HTTPS with TLS verification
// disabled. During initial bootstrap the CA does not yet exist on the target nodes,
// so the health check cannot validate certificates. A warning is logged on creation.
func newHTTPHealthChecker(logger *slog.Logger) *httpHealthChecker {
	logger.Warn("bootstrap: health checker using insecure TLS (CA not yet bootstrapped)")
	// Force the pure-Go DNS resolver to avoid SIGFPE in CGO's getaddrinfo
	// when running as a statically linked binary with glibc. The CGO resolver
	// calls glibc's getaddrinfo which can crash with a floating-point
	// exception in certain static-linking configurations.
	goResolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{
		Timeout:  10 * time.Second,
		Resolver: goResolver,
	}
	return &httpHealthChecker{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Required during initial bootstrap before CA exists.
				},
			},
		},
		logger: logger,
	}
}

// Check performs an HTTPS GET to the node's health endpoint.
func (h *httpHealthChecker) Check(ctx context.Context, address string) error {
	url := "https://" + address + ":8443/api/v1/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrHealthCheckFailed{
			Address: address,
		}
	}
	return nil
}
