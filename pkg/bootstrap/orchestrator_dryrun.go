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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"gopkg.in/yaml.v3"
)

const (
	// dryRunStatusReady indicates the node passed dry-run validation.
	dryRunStatusReady = "ready"

	// dryRunStatusUnreachable indicates the node's BMC was not reachable.
	dryRunStatusUnreachable = "unreachable"

	// dryRunStatusManual indicates the node is manually managed (no BMC).
	dryRunStatusManual = "manual"

	// dryRunStatusMissingMAC indicates a manual node is missing its MAC address.
	dryRunStatusMissingMAC = "missing-mac"
)

// DryRunResult holds the outcome of a bootstrap dry-run validation.
type DryRunResult struct {
	ConfigValid       bool               `json:"config_valid" yaml:"config_valid"`
	NodeCount         int                `json:"node_count" yaml:"node_count"`
	ControlPlaneCount int                `json:"control_plane_count" yaml:"control_plane_count"`
	GatewayCount      int                `json:"gateway_count" yaml:"gateway_count"`
	WorkerCount       int                `json:"worker_count" yaml:"worker_count"`
	SwitchConfigured  bool               `json:"switch_configured" yaml:"switch_configured"`
	SwitchVendor      string             `json:"switch_vendor,omitempty" yaml:"switch_vendor,omitempty"`
	SwitchPlan        *SwitchPlan        `json:"switch_plan,omitempty" yaml:"switch_plan,omitempty"`
	DeployerTarget    string             `json:"deployer_target" yaml:"deployer_target"`
	DeployerHost      string             `json:"deployer_host" yaml:"deployer_host"`
	CiscoCommands     string             `json:"cisco_commands,omitempty" yaml:"cisco_commands,omitempty"`
	Nodes             []DryRunNodeResult `json:"nodes" yaml:"nodes"`
	Errors            []string           `json:"errors,omitempty" yaml:"errors,omitempty"`
	Warnings          []string           `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	Duration          time.Duration      `json:"duration" yaml:"duration"`
}

// DryRunNodeResult holds validation results for a single node.
type DryRunNodeResult struct {
	Hostname       string   `json:"hostname" yaml:"hostname"`
	Role           string   `json:"role" yaml:"role"`
	BMCAddress     string   `json:"bmc_address,omitempty" yaml:"bmc_address,omitempty"`
	BMCProtocol    string   `json:"bmc_protocol,omitempty" yaml:"bmc_protocol,omitempty"`
	BMCReachable   bool     `json:"bmc_reachable" yaml:"bmc_reachable"`
	BMCManaged     bool     `json:"bmc_managed" yaml:"bmc_managed"`
	MACs           []string `json:"macs,omitempty" yaml:"macs,omitempty"`
	DiscoveredMACs []string `json:"discovered_macs,omitempty" yaml:"discovered_macs,omitempty"`
	ResolvedConfig string   `json:"resolved_config,omitempty" yaml:"resolved_config,omitempty"`
	Status         string   `json:"status" yaml:"status"`
	Error          string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// SwitchPlan describes the planned switch configuration changes.
type SwitchPlan struct {
	Vendor string     `json:"vendor" yaml:"vendor"`
	Host   string     `json:"host" yaml:"host"`
	VLANs  []VLANPlan `json:"vlans" yaml:"vlans"`
	Ports  []PortPlan `json:"ports" yaml:"ports"`
}

// VLANPlan describes a VLAN that will be created or updated.
type VLANPlan struct {
	ID     int    `json:"id" yaml:"id"`
	Name   string `json:"name" yaml:"name"`
	Subnet string `json:"subnet" yaml:"subnet"`
}

// PortPlan describes a port that will be configured.
type PortPlan struct {
	Port        string `json:"port" yaml:"port"`
	Mode        string `json:"mode" yaml:"mode"`
	VLANs       []int  `json:"vlans" yaml:"vlans"`
	Description string `json:"description" yaml:"description"`
}

// DryRun validates the bootstrap configuration, tests BMC connectivity for
// all managed nodes, and returns a plan of what would happen during a real
// bootstrap run. It does NOT deploy containers, configure switches, power
// on nodes, or make any infrastructure changes.
func (o *Orchestrator) DryRun(ctx context.Context) (*DryRunResult, error) {
	start := time.Now()

	result := &DryRunResult{
		DeployerTarget: o.config.Deployer.Target,
		DeployerHost:   o.config.Deployer.Host,
	}

	// Validate config.
	if err := o.config.Validate(); err != nil {
		result.ConfigValid = false
		result.Errors = append(result.Errors, err.Error())
		result.Duration = time.Since(start)
		return result, err
	}
	result.ConfigValid = true

	// Count nodes by role.
	if len(o.config.Nodes) == 0 {
		result.Duration = time.Since(start)
		return result, ErrDryRunNoNodes{}
	}

	roleCounts := o.countNodesByRole()
	result.NodeCount = len(o.config.Nodes)
	result.ControlPlaneCount = roleCounts[RoleControlPlane]
	result.GatewayCount = roleCounts[RoleGateway]
	result.WorkerCount = roleCounts[RoleWorker]

	// Switch info.
	if o.config.Switch != nil {
		result.SwitchConfigured = true
		result.SwitchVendor = o.config.Switch.Vendor
		result.SwitchPlan = o.buildSwitchPlan()
	} else {
		result.Warnings = append(result.Warnings,
			"switch management is optional, not configured")
	}

	// Test BMC reachability and discover MACs for all nodes concurrently.
	result.Nodes = o.dryRunNodes(ctx)

	// Resolve device configs for each node.
	o.logger.Info("dry-run: resolving device configurations")
	for i := range result.Nodes {
		nodeResult := &result.Nodes[i]
		resolvedYAML, err := o.resolveNodeConfig(nodeResult.Hostname, nodeResult.Role)
		if err != nil {
			nodeResult.Error = "config resolution failed: " + err.Error()
			result.Warnings = append(result.Warnings,
				"could not resolve config for "+nodeResult.Hostname+": "+err.Error())
			continue
		}
		nodeResult.ResolvedConfig = resolvedYAML
	}

	// Collect node-level errors into result.Errors for summary.
	for i := range result.Nodes {
		if result.Nodes[i].Error != "" {
			result.Errors = append(result.Errors, result.Nodes[i].Error)
		}
	}

	// Log the execution plan.
	o.logExecutionPlan(result)

	result.Duration = time.Since(start)
	return result, nil
}

// buildSwitchPlan creates a SwitchPlan from the switch configuration. VLANs
// are sorted by ID for deterministic output.
func (o *Orchestrator) buildSwitchPlan() *SwitchPlan {
	if o.config.Switch == nil {
		return nil
	}
	plan := &SwitchPlan{
		Vendor: o.config.Switch.Vendor,
		Host:   o.config.Switch.Host,
	}
	for name, def := range o.config.Switch.VLANs {
		plan.VLANs = append(plan.VLANs, VLANPlan{
			ID:     def.VLAN,
			Name:   name,
			Subnet: def.Subnet,
		})
	}
	sort.Slice(plan.VLANs, func(i, j int) bool {
		return plan.VLANs[i].ID < plan.VLANs[j].ID
	})
	for i := range o.config.Switch.PortAssignments {
		pa := &o.config.Switch.PortAssignments[i]
		plan.Ports = append(plan.Ports, PortPlan{
			Port:        pa.Port,
			Mode:        pa.Mode,
			VLANs:       pa.VLANs,
			Description: pa.Description,
		})
	}
	return plan
}

// resolveNodeConfig loads the template for the given role, applies per-node
// overrides from the bootstrap config, applies global platform identity, and
// returns the final YAML as a string.
func (o *Orchestrator) resolveNodeConfig(hostname, role string) (string, error) {
	templatePath, ok := o.config.Templates[role]
	if !ok {
		return "", ErrTemplateNotFoundForRole{Role: role}
	}

	// Resolve relative template paths against the bootstrap config file's directory.
	if !filepath.IsAbs(templatePath) && o.configDir != "" {
		templatePath = filepath.Join(o.configDir, templatePath)
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrTemplateFileNotFound{Role: role, Path: templatePath}
		}
		return "", ErrTemplateReadFailed{Role: role, Path: templatePath, Cause: err}
	}

	var templateMap map[string]interface{}
	if err := yaml.Unmarshal(data, &templateMap); err != nil {
		return "", ErrTemplateReadFailed{Role: role, Path: templatePath, Cause: err}
	}

	// Find the matching NodeConfig by hostname.
	var node *NodeConfig
	for i := range o.config.Nodes {
		if o.config.Nodes[i].Hostname == hostname {
			node = &o.config.Nodes[i]
			break
		}
	}

	// Apply global identity BEFORE the node overrides so the precedence
	// chain is: template -> platform global identity -> per-node overrides
	// -> ApplyNodeIdentity. Templates ship non-empty example placeholders,
	// so the platform values must overwrite them; a per-node override that
	// differs from the platform global still wins because overrides merge
	// after.
	applyGlobalIdentity(templateMap, &o.config.Platform)

	// Apply per-node overrides.
	if node != nil && len(node.Overrides) > 0 {
		templateMap = deepMerge(templateMap, node.Overrides)
	}

	// Inject the node's authoritative first-class fields (hostname, BMC
	// block, static interfaces). Overwrites unconditionally — validation
	// guarantees overrides never carry these keys.
	if node != nil {
		if err := ApplyNodeIdentity(templateMap, node); err != nil {
			return "", ErrTemplateMergeFailed{Hostname: hostname, Role: role, Cause: err}
		}
	}

	// Point non-CP nodes at the control plane's IP for DNS. The CP
	// runs the authoritative DNS service for the internal + public
	// zones; FQDNs (ACME directory URL, webservice SANs) resolve via
	// that resolver. Hard-coding /etc/hosts entries was considered and
	// rejected — DNS is the operator-correct path because it also
	// covers newly-issued services (dynamic zone updates) and keeps
	// TLS SAN validation aligned with whatever platformd's DNS
	// service publishes.
	if role != RoleControlPlane {
		o.injectControlPlaneDNS(templateMap)
	} else {
		// CP needs a dnsmasq forwarder too so platformd's own libc
		// lookups (e.g. ACME http-01 challenge validation — CP dials
		// the client at http://<gw-fqdn>:80/) resolve through the
		// authoritative zone that CP itself serves on 127.0.0.1:9053.
		// Without this, resolv.conf → 127.0.0.1:53 (no listener) →
		// "connection refused" and the ACME server can't validate
		// any http-01/tls-alpn challenge.
		o.injectControlPlaneSelfDNS(templateMap)
	}

	resolved, err := yaml.Marshal(templateMap)
	if err != nil {
		return "", ErrTemplateReadFailed{Role: role, Path: templatePath, Cause: err}
	}

	return string(resolved), nil
}

// injectControlPlaneDNS wires non-CP nodes to the control plane's
// authoritative DNS via a LOCAL dnsmasq forwarder. Why not point
// /etc/resolv.conf straight at the CP's IP?
//
//	Because platformd does not run as root — its DNS service binds
//	to port 9053 (internal zone) and 8053 (public zone), not the
//	privileged 53. libc resolvers always query :53, so every client
//	gets its own local dnsmasq (listening on 127.0.0.1:53) that
//	forwards upstream to <cp_ip>#9053. Result: resolv.conf stays at
//	localhost, dnsmasq handles the port mapping, and platformd
//	never needs CAP_NET_BIND_SERVICE.
//
// Sets `network.dns.upstream-dns: "<cp_ip>#9053"`. The Alpine
// installer's configureDNSWithDnsmasq (alpine.go) picks this up:
// installs dnsmasq, writes /etc/dnsmasq.conf with server=<cp_ip>#9053,
// enables the service at boot, and writes resolv.conf with
// nameserver 127.0.0.1. Search-domains are populated from the public
// + internal zones.
func (o *Orchestrator) injectControlPlaneDNS(templateMap map[string]interface{}) {
	var cpNode *NodeConfig
	for i := range o.config.Nodes {
		if o.config.Nodes[i].Role == RoleControlPlane {
			cpNode = &o.config.Nodes[i]
			break
		}
	}
	if cpNode == nil {
		return
	}

	cpIPs := cpNode.StaticIPv4s()
	if len(cpIPs) == 0 {
		return
	}
	cpIP := cpIPs[0]
	// CP internal DNS port — matches dns.internal.port in the CP
	// template. Kept in sync via the defaultInternalDNSPort constant
	// so a template change doesn't silently break client resolution.
	upstream := cpIP + "#" + defaultInternalDNSPort

	network, ok := templateMap["network"].(map[string]interface{})
	if !ok {
		network = map[string]interface{}{}
		templateMap["network"] = network
	}
	dns, ok := network["dns"].(map[string]interface{})
	if !ok {
		dns = map[string]interface{}{}
		network["dns"] = dns
	}
	dns["upstream-dns"] = upstream

	// Search-domain list so bare hostnames resolve against the
	// deployment's zones. dnsmasq doesn't own this — /etc/resolv.conf
	// does — so the installer writes it from DNS.SearchDomains.
	searchDomains := make(map[string]struct{})
	addSearchDomain := func(d string) {
		d = strings.TrimSpace(d)
		if d != "" {
			searchDomains[d] = struct{}{}
		}
	}
	if s, _ := templateMap["domain"].(string); s != "" {
		addSearchDomain(s)
	}
	if s, _ := templateMap["internal-domain"].(string); s != "" {
		addSearchDomain(s)
	}
	if s, _ := templateMap["internal_domain"].(string); s != "" {
		addSearchDomain(s)
	}
	addSearchDomain(o.config.Platform.Domain)
	addSearchDomain(o.config.Platform.InternalDomain)

	if len(searchDomains) > 0 {
		sd := make([]interface{}, 0, len(searchDomains))
		for s := range searchDomains {
			sd = append(sd, s)
		}
		dns["search-domains"] = sd
	}
}

// defaultInternalDNSPort is the port platformd's internal DNS zone
// listens on (non-privileged; see CP template dns.internal.port).
// Clients forward to it via local dnsmasq.
const defaultInternalDNSPort = "9053"

// injectControlPlaneSelfDNS wires the CP to forward libc resolver
// traffic (resolv.conf → 127.0.0.1:53) to its OWN platformd DNS
// authoritative zone on 127.0.0.1:9053. Same dnsmasq pattern as
// client nodes, just with the upstream pointing at loopback
// instead of CP's public IP.
//
// This is needed for any CP-side lookup platformd itself triggers —
// chief among them ACME http-01 challenge validation, where the
// ACME server dials http://<gw-fqdn>:80/.well-known/acme-challenge/…
// to verify the client published the expected token.
func (o *Orchestrator) injectControlPlaneSelfDNS(templateMap map[string]interface{}) {
	network, ok := templateMap["network"].(map[string]interface{})
	if !ok {
		network = map[string]interface{}{}
		templateMap["network"] = network
	}
	dns, ok := network["dns"].(map[string]interface{})
	if !ok {
		dns = map[string]interface{}{}
		network["dns"] = dns
	}
	dns["upstream-dns"] = "127.0.0.1#" + defaultInternalDNSPort

	searchDomains := make(map[string]struct{})
	addSearchDomain := func(d string) {
		d = strings.TrimSpace(d)
		if d != "" {
			searchDomains[d] = struct{}{}
		}
	}
	if s, _ := templateMap["domain"].(string); s != "" {
		addSearchDomain(s)
	}
	if s, _ := templateMap["internal-domain"].(string); s != "" {
		addSearchDomain(s)
	}
	if s, _ := templateMap["internal_domain"].(string); s != "" {
		addSearchDomain(s)
	}
	addSearchDomain(o.config.Platform.Domain)
	addSearchDomain(o.config.Platform.InternalDomain)
	if len(searchDomains) > 0 {
		sd := make([]interface{}, 0, len(searchDomains))
		for s := range searchDomains {
			sd = append(sd, s)
		}
		dns["search-domains"] = sd
	}
}

// applyGlobalIdentity overwrites the top-level identity keys with the
// non-empty platform global values. The overwrite is unconditional because
// role templates ship non-empty example placeholders — a fill-if-empty
// policy would leave those placeholders in resolved configs. It runs BEFORE
// the per-node override merge, so a per-node identity override still wins.
// Mirrors seeder.go::applyGlobalIdentitySeeder.
func applyGlobalIdentity(m map[string]interface{}, platform *PlatformGlobalConfig) {
	if platform == nil {
		return
	}
	setGlobal := func(key, value string) {
		if value == "" {
			return
		}
		m[key] = value
	}
	setGlobal("domain", platform.Domain)
	setGlobal("hostmaster", platform.Hostmaster)
	setGlobal("tenant-id", platform.TenantID)
	setGlobal("environment", platform.Environment)
}

// deepMerge recursively merges src into dst. src values take precedence.
func deepMerge(dst, src map[string]interface{}) map[string]interface{} {
	for key, srcVal := range src {
		if srcMap, ok := srcVal.(map[string]interface{}); ok {
			if dstMap, ok := dst[key].(map[string]interface{}); ok {
				dst[key] = deepMerge(dstMap, srcMap)
				continue
			}
		}
		dst[key] = srcVal
	}
	return dst
}

// countNodesByRole returns a map of role to count for all configured nodes.
func (o *Orchestrator) countNodesByRole() map[string]int {
	counts := make(map[string]int, len(validRoles))
	for i := range o.config.Nodes {
		counts[o.config.Nodes[i].Role]++
	}
	return counts
}

// dryRunNodeWork holds the input and output for a single node's dry-run validation.
type dryRunNodeWork struct {
	index  int
	result DryRunNodeResult
}

// dryRunNodes validates all nodes concurrently and returns ordered results.
func (o *Orchestrator) dryRunNodes(ctx context.Context) []DryRunNodeResult {
	results := make([]DryRunNodeResult, len(o.config.Nodes))
	workCh := make(chan *dryRunNodeWork, len(o.config.Nodes))

	var wg sync.WaitGroup

	for i := range o.config.Nodes {
		node := &o.config.Nodes[i]
		wg.Add(1)
		go func(idx int, n *NodeConfig) {
			defer wg.Done()
			nr := o.dryRunSingleNode(ctx, n)
			workCh <- &dryRunNodeWork{index: idx, result: nr}
		}(i, node)
	}

	go func() {
		wg.Wait()
		close(workCh)
	}()

	for work := range workCh {
		results[work.index] = work.result
	}

	return results
}

// dryRunSingleNode validates a single node: tests BMC connectivity (read-only)
// for BMC-managed nodes, or verifies MAC presence for manual nodes.
func (o *Orchestrator) dryRunSingleNode(ctx context.Context, node *NodeConfig) DryRunNodeResult {
	nr := DryRunNodeResult{
		Hostname:   node.Hostname,
		Role:       node.Role,
		BMCAddress: node.BMCAddress,
		MACs:       append([]string(nil), node.MACs...),
	}

	if node.IsBMCManaged() {
		nr.BMCManaged = true
		nr.BMCProtocol = node.BMCProtocol
		o.dryRunBMCNode(ctx, node, &nr)
		return nr
	}

	// Manual node: verify at least one MAC is present.
	if len(node.MACs) == 0 {
		nr.Status = dryRunStatusMissingMAC
		nr.Error = "manual node " + node.Hostname + " is missing mac address"
		return nr
	}

	nr.Status = dryRunStatusManual
	return nr
}

// dryRunBMCNode tests BMC reachability using a read-only PowerStatus call and
// attempts read-only MAC discovery via bmc.DiscoverMAC. No write operations
// are performed.
func (o *Orchestrator) dryRunBMCNode(ctx context.Context, node *NodeConfig, nr *DryRunNodeResult) {
	bmcConfig := buildBMCConfig(node, o.bmcTLSProvider)

	client, err := o.bmcFactory.NewClient(bmcConfig)
	if err != nil {
		nr.BMCReachable = false
		nr.Status = dryRunStatusUnreachable
		bmcErr := ErrDryRunBMCUnreachable{
			Hostname:   node.Hostname,
			BMCAddress: node.BMCAddress,
			Cause:      err,
		}
		nr.Error = bmcErr.Error()
		o.logger.Warn("bootstrap: dry-run: bmc client creation failed",
			slog.String("hostname", node.Hostname),
			slog.String("bmc_address", node.BMCAddress),
			slog.String("error", err.Error()))
		return
	}
	defer client.Close()

	// Read-only: query power status to test connectivity.
	_, err = client.PowerStatus(ctx)
	if err != nil {
		nr.BMCReachable = false
		nr.Status = dryRunStatusUnreachable
		bmcErr := ErrDryRunBMCUnreachable{
			Hostname:   node.Hostname,
			BMCAddress: node.BMCAddress,
			Cause:      err,
		}
		nr.Error = bmcErr.Error()
		o.logger.Warn("bootstrap: dry-run: bmc unreachable",
			slog.String("hostname", node.Hostname),
			slog.String("bmc_address", node.BMCAddress),
			slog.String("error", err.Error()))
		return
	}

	nr.BMCReachable = true

	// Best-effort read-only MAC discovery via Redfish EthernetInterfaces.
	macs, macErr := bmc.DiscoverMACs(ctx, bmcConfig, o.logger)
	if macErr == nil && len(macs) > 0 {
		nr.DiscoveredMACs = macs
	} else if macErr != nil {
		o.logger.Debug("bootstrap: dry-run: mac discovery failed (best-effort)",
			slog.String("hostname", node.Hostname),
			slog.String("error", macErr.Error()))
	}

	nr.Status = dryRunStatusReady
}

// logExecutionPlan logs the full execution plan that would be performed during
// a real bootstrap run.
func (o *Orchestrator) logExecutionPlan(result *DryRunResult) {
	bmcManagedCount := 0
	for i := range result.Nodes {
		if result.Nodes[i].BMCManaged {
			bmcManagedCount++
		}
	}

	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_0", "discover MACs from BMC-managed nodes"),
		slog.Int("bmc_managed_count", bmcManagedCount))

	if result.SwitchConfigured {
		vlanCount := 0
		portCount := 0
		if o.config.Switch != nil {
			vlanCount = len(o.config.Switch.VLANs)
			portCount = len(o.config.Switch.PortAssignments)
		}
		o.logger.Info("bootstrap: dry-run: execution plan",
			slog.String("phase_1", "configure switch"),
			slog.String("vendor", result.SwitchVendor),
			slog.Int("vlans", vlanCount),
			slog.Int("ports", portCount))
	} else {
		o.logger.Info("bootstrap: dry-run: execution plan",
			slog.String("phase_1", "skip switch configuration (not configured)"))
	}

	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_2", "deploy bootstrap container"),
		slog.String("host", result.DeployerHost),
		slog.String("target", result.DeployerTarget))

	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_3", "PXE boot control-plane nodes"),
		slog.Int("count", result.ControlPlaneCount))

	templateCount := len(o.config.Templates)
	profileCount := len(o.config.Nodes)
	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_4", "seed templates and create profiles"),
		slog.Int("templates", templateCount),
		slog.Int("profiles", profileCount))

	remainingCount := result.GatewayCount + result.WorkerCount
	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_5", "PXE boot remaining nodes"),
		slog.Int("gateways", result.GatewayCount),
		slog.Int("workers", result.WorkerCount),
		slog.Int("total", remainingCount))

	o.logger.Info("bootstrap: dry-run: execution plan",
		slog.String("phase_6", "teardown bootstrap container"))
}
