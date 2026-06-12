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
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

const (
	// defaultBMCTimeout is the default timeout for BMC operations during discovery.
	defaultBMCTimeout = 30 * time.Second

	// defaultRedfishPort is the default HTTPS port for Redfish BMC access.
	defaultRedfishPort = 443

	// defaultIPMIPort is the default UDP port for IPMI BMC access.
	defaultIPMIPort = 623
)

// DiscoveredNode is a node with its MAC address resolved from either BMC
// auto-discovery or manual configuration.
type DiscoveredNode struct {
	NodeConfig
	DiscoveredMACs []string        `json:"discovered_macs" yaml:"discovered_macs"`
	SystemInfo     *bmc.SystemInfo `json:"system_info,omitempty" yaml:"system_info,omitempty"`
	BMCManaged     bool            `json:"bmc_managed" yaml:"bmc_managed"`
}

// discoveryResult holds the outcome of a single node's discovery goroutine.
type discoveryResult struct {
	index int
	node  DiscoveredNode
	err   error
}

// DiscoveryOptions carries optional collaborators for node discovery.
// The zero value is valid: when TLSProvider is nil, BMC connections use
// system roots with TLS 1.2+ minimum (the secure default from BuildTLSConfig).
type DiscoveryOptions struct {
	// TLSProvider is injected by the orchestrator so every BMC connection
	// uses the run-scoped trust resolver. When nil, system roots are used.
	TLSProvider bmc.TLSProvider
}

// DiscoverNodes iterates all nodes, queries BMCs for MAC addresses on
// BMC-managed nodes, and returns a unified list of discovered nodes.
// BMC discovery runs concurrently across all BMC-managed nodes.
// Nodes with SkipInstall set are included without BMC or MAC discovery.
func DiscoverNodes(ctx context.Context, nodes []NodeConfig, logger *slog.Logger, opts ...DiscoveryOptions) ([]DiscoveredNode, error) {
	if len(nodes) == 0 {
		return nil, ErrInvalidBootstrapConfig{Reason: "no nodes to discover"}
	}

	var o DiscoveryOptions
	if len(opts) > 0 {
		o = opts[0]
	}

	results := make([]DiscoveredNode, len(nodes))
	resultCh := make(chan discoveryResult, len(nodes))

	var wg sync.WaitGroup

	for i := range nodes {
		node := &nodes[i]

		// SkipInstall nodes are already deployed -- no BMC or MAC
		// discovery needed. Copy any operator-provided MACs but don't
		// fail if none are present.
		if node.SkipInstall {
			logger.Info("bootstrap: skipping discovery for skip_install node",
				slog.String("hostname", node.Hostname),
				slog.String("role", node.Role))
			results[i] = DiscoveredNode{
				NodeConfig:     *node,
				DiscoveredMACs: append([]string(nil), node.MACs...),
				BMCManaged:     node.IsBMCManaged(),
			}
			continue
		}

		if node.IsManual() {
			results[i] = DiscoveredNode{
				NodeConfig:     *node,
				DiscoveredMACs: append([]string(nil), node.MACs...),
				BMCManaged:     false,
			}
			continue
		}

		wg.Add(1)
		go func(idx int, n *NodeConfig) {
			defer wg.Done()
			discovered, err := discoverBMCNode(ctx, n, o.TLSProvider, logger)
			resultCh <- discoveryResult{index: idx, node: discovered, err: err}
		}(i, node)
	}

	// Close the channel once all goroutines complete.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results from concurrent BMC discovery.
	for result := range resultCh {
		if result.err != nil {
			return nil, ErrNodeDiscoveryFailed{
				Hostname: nodes[result.index].Hostname,
				Cause:    result.err,
			}
		}
		results[result.index] = result.node
	}

	return results, nil
}

// discoverBMCNode performs MAC and system info discovery for a single BMC-managed node.
func discoverBMCNode(ctx context.Context, node *NodeConfig, tlsProvider bmc.TLSProvider, logger *slog.Logger) (DiscoveredNode, error) {
	bmcConfig := buildBMCConfig(node, tlsProvider)

	// Discover protocol if set to auto or empty.
	if bmcConfig.Protocol == "" || node.BMCProtocol == "auto" {
		detected := bmc.DetectProtocol(ctx, node.BMCAddress, defaultBMCTimeout)
		if detected == "" {
			return DiscoveredNode{}, ErrMACDiscoveryFailed{
				BMCAddress: node.BMCAddress,
				Cause:      bmc.ErrProtocolDetectionFailed{Address: node.BMCAddress},
			}
		}
		bmcConfig.Protocol = detected
	}

	// Discover all MAC addresses (the BIOS may PXE-boot from any onboard NIC).
	//
	// Prior behavior: when the operator pre-populated MACs in bootstrap.yaml,
	// BMC discovery was skipped entirely. That produced a fatal gap on multi-NIC
	// hosts where the operator only listed the PXE-boot MAC but the installed
	// OS's primary NIC (picked by eth0 enumeration) carries a different MAC.
	// Per-MAC downstream lookups (install-log upload path, hostname config fetch,
	// health registration) would miss because the NIC eth0 maps to wasn't in
	// the known-MAC set.
	//
	// New behavior: treat YAML MACs as a seed, then union with BMC-discovered
	// MACs so every onboard+addin NIC is represented. Operator-provided MACs
	// still appear first so pxe_config.go and other MAC-order-sensitive code
	// paths keep seeing their authoritative value up front.
	var macs []string
	seen := map[string]struct{}{}
	add := func(m string) {
		lm := strings.ToLower(strings.TrimSpace(m))
		if lm == "" {
			return
		}
		if _, ok := seen[lm]; ok {
			return
		}
		seen[lm] = struct{}{}
		macs = append(macs, m)
	}
	for _, m := range node.MACs {
		add(m)
	}
	discovered, discoverErr := bmc.DiscoverMACs(ctx, bmcConfig, logger)
	if discoverErr != nil {
		if len(macs) == 0 {
			return DiscoveredNode{}, ErrMACDiscoveryFailed{
				BMCAddress: node.BMCAddress,
				Cause:      discoverErr,
			}
		}
		logger.Warn("bootstrap: BMC MAC discovery failed, using operator-provided MACs only",
			slog.String("hostname", node.Hostname),
			slog.Int("yaml_macs", len(macs)),
			slog.String("error", discoverErr.Error()))
	} else {
		for _, m := range discovered {
			add(m)
		}
	}
	logger.Debug("bootstrap: resolved node MACs",
		slog.String("hostname", node.Hostname),
		slog.Int("yaml_count", len(node.MACs)),
		slog.Int("total_count", len(macs)))

	// Attempt to retrieve system info (best effort).
	var sysInfo *bmc.SystemInfo
	factory := bmc.NewDefaultClientFactory(logger)
	client, clientErr := factory.NewClient(bmcConfig)
	if clientErr == nil {
		defer client.Close()
		info, infoErr := client.GetSystemInfo(ctx)
		if infoErr == nil {
			sysInfo = info
		} else {
			logger.Debug("bootstrap: system info retrieval failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", infoErr.Error()))
		}
	}

	return DiscoveredNode{
		NodeConfig:     *node,
		DiscoveredMACs: macs,
		SystemInfo:     sysInfo,
		BMCManaged:     true,
	}, nil
}

// buildBMCConfig creates a bmc.Config from a NodeConfig's BMC fields.
// When tlsProvider is non-nil it is wired into cfg.TLS so BuildTLSConfig
// uses the trust resolver path; the secure system-roots default
// fields are not set.
func buildBMCConfig(node *NodeConfig, tlsProvider bmc.TLSProvider) *bmc.Config {
	config := &bmc.Config{
		Address:       node.BMCAddress,
		Username:      node.BMCUser,
		Password:      node.BMCPassword,
		EncryptionKey: node.BMCEncryptionKey,
		TLS:           tlsProvider,
	}

	switch node.BMCProtocol {
	case "redfish":
		config.Protocol = bmc.ProtocolRedfish
		config.Port = defaultRedfishPort
	case "ipmi":
		config.Protocol = bmc.ProtocolIPMI
		config.Port = defaultIPMIPort
	default:
		// Auto or empty: will be detected later.
		config.Protocol = bmc.ProtocolRedfish
		config.Port = defaultRedfishPort
	}

	return config
}
