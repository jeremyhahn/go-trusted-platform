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
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
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
	DeployerHost      string             `json:"deployer_host" yaml:"deployer_host"`
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
	// HardwareIdentity is the identity the node's BMC client resolves its
	// own pkg/quirks entry from, read from that client during the dry run
	// so the previewed config shows the hardware keys a real run writes.
	// Nil when the node has no BMC or the BMC named nothing.
	HardwareIdentity *quirks.Identity `json:"hardware_identity,omitempty" yaml:"hardware_identity,omitempty"`
	// Warnings are pre-flight findings that do not block the run but
	// predict trouble: a full System Event Log, memory faults on record.
	// They are also folded into DryRunResult.Warnings.
	Warnings []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
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

// PortPlan describes a port that will be configured: its class and what
// the class carries on this deployment's network plan.
type PortPlan struct {
	Port        string `json:"port" yaml:"port"`
	Class       string `json:"class" yaml:"class"`
	Mode        string `json:"mode" yaml:"mode"`
	VLANs       []int  `json:"vlans" yaml:"vlans"`
	NativeVLAN  int    `json:"native_vlan,omitempty" yaml:"native_vlan,omitempty"`
	MTU         int    `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	Description string `json:"description" yaml:"description"`
}

// DryRun validates the bootstrap configuration, tests BMC connectivity for
// all managed nodes, and returns a plan of what would happen during a real
// bootstrap run. It does NOT deploy containers, configure switches, power
// on nodes, or make any infrastructure changes.
func (o *Orchestrator) DryRun(ctx context.Context) (*DryRunResult, error) {
	start := time.Now()

	result := &DryRunResult{
		DeployerHost: o.config.Deployer.Host,
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
		switchPlan, err := o.buildSwitchPlan()
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Duration = time.Since(start)
			return result, err
		}
		result.SwitchPlan = switchPlan
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
		resolvedYAML, err := o.resolveNodeConfig(nodeResult.Hostname, nodeResult.Role, nodeResult.HardwareIdentity)
		if err != nil {
			nodeResult.Error = "config resolution failed: " + err.Error()
			result.Warnings = append(result.Warnings,
				"could not resolve config for "+nodeResult.Hostname+": "+err.Error())
			continue
		}
		nodeResult.ResolvedConfig = resolvedYAML
	}

	// Collect node-level errors and warnings into the summary.
	for i := range result.Nodes {
		if result.Nodes[i].Error != "" {
			result.Errors = append(result.Errors, result.Nodes[i].Error)
		}
		result.Warnings = append(result.Warnings, result.Nodes[i].Warnings...)
	}

	// Log the execution plan.
	o.logExecutionPlan(result)

	result.Duration = time.Since(start)
	return result, nil
}

// buildSwitchPlan reports what the switch phase would program: the same
// switchmgmt configuration configureSwitch applies, derived from the network
// plan, with each port's class alongside. VLANs are sorted by ID.
func (o *Orchestrator) buildSwitchPlan() (*SwitchPlan, error) {
	if o.config.Switch == nil {
		return nil, nil
	}
	plan, err := o.config.NetworkPlan()
	if err != nil {
		return nil, err
	}
	swConfig, err := buildSwitchConfig(o.config.Switch, plan)
	if err != nil {
		return nil, err
	}
	out := &SwitchPlan{
		Vendor: o.config.Switch.Vendor,
		Host:   o.config.Switch.Host,
	}
	for _, v := range swConfig.VLANs {
		out.VLANs = append(out.VLANs, VLANPlan{ID: v.ID, Name: v.Name, Subnet: v.Subnet})
	}
	for i, p := range swConfig.Ports {
		vlans := p.VLANs
		if p.Mode == string(netplan.PortModeAccess) {
			vlans = []int{p.AccessVLAN}
		}
		out.Ports = append(out.Ports, PortPlan{
			Port:        p.Port,
			Class:       string(o.config.Switch.PortAssignments[i].Class),
			Mode:        p.Mode,
			VLANs:       vlans,
			NativeVLAN:  p.NativeVLAN,
			MTU:         p.MTU,
			Description: p.Description,
		})
	}
	return out, nil
}

// ResolvedNodeConfig is one node's platform config as bootstrap writes it:
// its role template merged with the platform identity, the node's
// overrides and its node identity.
type ResolvedNodeConfig struct {
	Hostname string
	Role     string
	Config   string
}

// ResolveNodeConfigs resolves the platform config of every node in the
// bootstrap config, or of the named hosts only, in config order. Nothing is
// contacted: the hardware keys a real run reads from each node's BMC are
// absent, so the result is the config as the deployment defines it.
func (o *Orchestrator) ResolveNodeConfigs(hostnames ...string) ([]ResolvedNodeConfig, error) {
	wanted := make(map[string]bool, len(hostnames))
	for _, h := range hostnames {
		wanted[h] = true
	}
	var resolved []ResolvedNodeConfig
	for _, n := range o.config.Nodes {
		if len(wanted) > 0 && !wanted[n.Hostname] {
			continue
		}
		delete(wanted, n.Hostname)
		cfg, err := o.resolveNodeConfig(n.Hostname, n.Role, nil)
		if err != nil {
			return nil, ErrNodeConfigResolveFailed{Hostname: n.Hostname, Cause: err}
		}
		resolved = append(resolved, ResolvedNodeConfig{Hostname: n.Hostname, Role: n.Role, Config: cfg})
	}
	for h := range wanted {
		return nil, ErrUnknownNode{Hostname: h}
	}
	return resolved, nil
}

// resolveNodeConfig loads the template for the given role, applies per-node
// overrides from the bootstrap config, applies global platform identity and
// the node's discovered hardware identity, and returns the final YAML as a
// string. hw is the identity the node's BMC client resolved its own quirk
// entry from; nil for a node with no BMC or a BMC that named nothing.
func (o *Orchestrator) resolveNodeConfig(hostname, role string, hw *quirks.Identity) (string, error) {
	templatePath, ok := o.config.TemplatePath(role, o.configDir)
	if !ok {
		return "", ErrTemplateNotFoundForRole{Role: role}
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

	// Hand the installer the identity the BMC client resolved its own
	// quirk entry from, so the installed OS selects the same entry.
	// Placed in the same slot as the global identity — after the template,
	// before the overrides — so an operator who pins the keys by hand for
	// a BMC that misreports itself still wins.
	applyHardwareIdentity(templateMap, hw)

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
	o.setSearchDomains(dns, templateMap)
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

	o.setSearchDomains(dns, templateMap)
}

// setSearchDomains writes network.dns.search-domains: the resolv.conf
// search list, in configuration order — the node's resolved domain, its
// internal domain (either key spelling), then the platform domain and the
// platform internal domain. A domain named twice keeps its first position.
// The order is fixed so that `platformctl bootstrap resolve` prints the same
// config on every run and an installed node's resolver tries its zones in
// the order the operator configured them. With no domain at all the key is
// left unset.
func (o *Orchestrator) setSearchDomains(dns, templateMap map[string]interface{}) {
	candidates := make([]string, 0, 5)
	for _, key := range []string{"domain", "internal-domain", "internal_domain"} {
		if s, ok := templateMap[key].(string); ok {
			candidates = append(candidates, s)
		}
	}
	candidates = append(candidates, o.config.Platform.Domain, o.config.Platform.InternalDomain)

	seen := make(map[string]struct{}, len(candidates))
	ordered := make([]interface{}, 0, len(candidates))
	for _, d := range candidates {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		ordered = append(ordered, d)
	}
	if len(ordered) > 0 {
		dns["search-domains"] = ordered
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
	applySPIFFETrustDomain(m, platform)
}

// applyHardwareIdentity writes the node's discovered hardware identity into
// the top-level installer keys (installer.Config's `hardware-manufacturer`,
// `hardware-model` and `hardware-part-number`), which pkg/installer feeds to
// quirks.ResolveIdentity when building the UKI cmdline and the Alpine
// installer. The three keys carry the SAME identity the BMC client matched
// on, which is the whole point: both sides land on one registry entry.
//
// A nil identity writes nothing and leaves whatever the template carried,
// so an unidentified BMC resolves quirks.Default(). Empty fields are
// written as empty strings rather than skipped: a template placeholder
// naming a different board must not survive a real discovery that could not
// read that field, or the two sides diverge exactly where it matters.
func applyHardwareIdentity(m map[string]interface{}, hw *quirks.Identity) {
	if hw == nil {
		return
	}
	m["hardware-manufacturer"] = hw.Manufacturer
	m["hardware-model"] = hw.Model
	m["hardware-part-number"] = hw.PartNumber
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

	// Read the identity this client resolves its own quirk entry from, so
	// the previewed config carries the same hardware keys the real run
	// writes and an operator can see which entry the node will land on.
	nr.HardwareIdentity = readHardwareIdentity(ctx, client, node.Hostname, o.logger)

	// Pre-flight: read the System Event Log and warn on anything that
	// predicts a failed install — a log that stopped recording, or memory
	// faults already on record. Read-only, best-effort: a BMC without a
	// log surface is simply not warned about.
	nr.Warnings = append(nr.Warnings, o.dryRunEventLog(ctx, client, node.Hostname)...)

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

// dryRunEventLog reads a node's SEL and returns the pre-flight warnings it
// implies. An unsupported log surface produces no warning; a read failure
// produces one, because "could not check" is itself worth knowing before a
// 45-minute run.
func (o *Orchestrator) dryRunEventLog(ctx context.Context, client bmc.Client, hostname string) []string {
	log, err := client.GetEventLog(ctx)
	if err != nil {
		var unsupported bmc.ErrUnsupportedOperation
		if errors.As(err, &unsupported) {
			o.logger.Debug("bootstrap: dry-run: event log not available on this controller",
				slog.String("hostname", hostname),
				slog.String("reason", err.Error()))
			return nil
		}
		o.logger.Warn("bootstrap: dry-run: event log read failed",
			slog.String("hostname", hostname),
			slog.String("error", err.Error()))
		return []string{hostname + ": system event log could not be read (" + err.Error() + ")"}
	}
	return eventLogWarnings(hostname, log)
}

// eventLogWarnings turns an EventLog into operator-facing pre-flight
// warnings: one for a log that has stopped recording, and one per faulting
// sensor summarising what is on record and when it was last seen.
func eventLogWarnings(hostname string, log *bmc.EventLog) []string {
	var warnings []string
	if log.Truncated {
		warnings = append(warnings, hostname+": system event log read stopped at "+strconv.Itoa(len(log.Entries))+
			" of "+strconv.Itoa(log.EntryCount)+" entries — faults in the unread part are not reported")
	}
	if log.Full() {
		msg := hostname + ": system event log is full — new hardware faults will not be recorded"
		if !log.LastAddition.IsZero() {
			msg += " (last entry " + log.LastAddition.Format(time.RFC3339) + ")"
		}
		warnings = append(warnings, msg+"; clear the SEL before provisioning")
	}

	type faultSummary struct {
		sensor        string
		count         int
		uncorrectable int
		last          time.Time
		lastMessage   string
	}
	order := make([]string, 0)
	bySensor := make(map[string]*faultSummary)
	for _, e := range log.MemoryFaults() {
		key := e.Sensor
		if key == "" {
			key = "sensor " + strconv.Itoa(int(e.SensorNumber))
		}
		fs := bySensor[key]
		if fs == nil {
			fs = &faultSummary{sensor: key}
			bySensor[key] = fs
			order = append(order, key)
		}
		fs.count++
		if e.EventOffset != bmc.MemoryEventCorrectableECC && e.EventOffset != bmc.MemoryEventCorrectableLimit {
			fs.uncorrectable++
		}
		if !e.Timestamp.Before(fs.last) {
			fs.last = e.Timestamp
			fs.lastMessage = e.Message
		}
	}
	for _, key := range order {
		fs := bySensor[key]
		msg := hostname + ": " + fs.sensor + " has " + strconv.Itoa(fs.count) + " memory fault"
		if fs.count != 1 {
			msg += "s"
		}
		msg += " on record"
		if fs.uncorrectable > 0 {
			msg += " (" + strconv.Itoa(fs.uncorrectable) + " uncorrectable)"
		}
		if fs.lastMessage != "" {
			msg += ", last: " + fs.lastMessage
			if !fs.last.IsZero() {
				msg += " at " + fs.last.Format(time.RFC3339)
			}
		}
		warnings = append(warnings, msg+" — expect POST to halt on this DIMM")
	}
	return warnings
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
		if result.SwitchPlan != nil {
			vlanCount = len(result.SwitchPlan.VLANs)
			portCount = len(result.SwitchPlan.Ports)
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
		slog.String("host", result.DeployerHost))

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
