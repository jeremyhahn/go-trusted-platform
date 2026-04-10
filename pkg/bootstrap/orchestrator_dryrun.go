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
	Hostname       string `json:"hostname" yaml:"hostname"`
	Role           string `json:"role" yaml:"role"`
	BMCAddress     string `json:"bmc_address,omitempty" yaml:"bmc_address,omitempty"`
	BMCProtocol    string `json:"bmc_protocol,omitempty" yaml:"bmc_protocol,omitempty"`
	BMCReachable   bool   `json:"bmc_reachable" yaml:"bmc_reachable"`
	BMCManaged     bool   `json:"bmc_managed" yaml:"bmc_managed"`
	MACs           []string `json:"macs,omitempty" yaml:"macs,omitempty"`
	DiscoveredMACs []string `json:"discovered_macs,omitempty" yaml:"discovered_macs,omitempty"`
	ResolvedConfig string `json:"resolved_config,omitempty" yaml:"resolved_config,omitempty"`
	Status         string `json:"status" yaml:"status"`
	Error          string `json:"error,omitempty" yaml:"error,omitempty"`
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

	// Apply per-node overrides.
	if node != nil && len(node.Overrides) > 0 {
		templateMap = deepMerge(templateMap, node.Overrides)
	}

	// Apply global identity: fill empty domain, hostmaster, tenant-id from platform config.
	applyGlobalIdentity(templateMap, &o.config.Platform)

	resolved, err := yaml.Marshal(templateMap)
	if err != nil {
		return "", ErrTemplateReadFailed{Role: role, Path: templatePath, Cause: err}
	}

	return string(resolved), nil
}

// applyGlobalIdentity fills empty top-level identity fields from the platform
// global configuration.
func applyGlobalIdentity(m map[string]interface{}, platform *PlatformGlobalConfig) {
	if val, ok := m["domain"]; ok {
		if s, isStr := val.(string); isStr && s == "" {
			m["domain"] = platform.Domain
		}
	}
	if val, ok := m["hostmaster"]; ok {
		if s, isStr := val.(string); isStr && s == "" {
			m["hostmaster"] = platform.Hostmaster
		}
	}
	if val, ok := m["tenant-id"]; ok {
		if s, isStr := val.(string); isStr && s == "" {
			m["tenant-id"] = platform.TenantID
		}
	}
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
	bmcConfig := buildBMCConfig(node)

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
