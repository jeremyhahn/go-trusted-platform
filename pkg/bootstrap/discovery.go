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
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
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
	// HardwareIdentity is the vendor/board identity the node's BMC client
	// resolves its own pkg/quirks entry from, read straight off that client
	// (bmc.Client.HardwareIdentity) rather than rebuilt from SystemInfo,
	// whose fields differ. The orchestrator writes it into the node's
	// installer config so the installed OS selects the same quirk entry the
	// BMC side did. Nil when the node has no BMC or the BMC named nothing.
	HardwareIdentity *quirks.Identity `json:"hardware_identity,omitempty" yaml:"hardware_identity,omitempty"`
	// EKCert is the optional PEM-encoded TPM Endorsement Key certificate
	// prestaged for this hardware node. Discovery cannot yet capture a
	// hardware EK directly, so this is supplied via the prestage input and
	// carried into the control-plane profile so EK-bound config delivery can
	// verify the device at boot. Hardware EK-capture UX is completed by the
	// Phase 3a prestage flow. Empty when no EK certificate was prestaged.
	EKCert string `json:"ek_cert,omitempty" yaml:"ek_cert,omitempty"`
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

	// ClientFactory builds the BMC client discovery reads system info and
	// the hardware identity through. The orchestrator injects its own
	// bmcFactory so discovery shares the seam every other BMC call site in
	// this package uses. When nil, bmc.NewDefaultClientFactory is used.
	ClientFactory bmc.ClientFactory
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
	factory := o.ClientFactory
	if factory == nil {
		factory = bmc.NewDefaultClientFactory(logger)
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
			discovered, err := discoverBMCNode(ctx, n, o.TLSProvider, factory, logger)
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
func discoverBMCNode(ctx context.Context, node *NodeConfig, tlsProvider bmc.TLSProvider, factory bmc.ClientFactory, logger *slog.Logger) (DiscoveredNode, error) {
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

	// Attempt to retrieve the quirk-matching hardware identity and system
	// info (both best effort).
	//
	// The identity is read FIRST. Its read retries discovery fresh
	// (bmc.Client.HardwareIdentity bypasses the Redfish negative cache),
	// whereas GetSystemInfo is served that cache. Read the other way round,
	// a discovery blip failed GetSystemInfo, the identity retry then
	// recovered discovery, and the node kept no system info even though the
	// client had since learned the answer (#206). In this order system info
	// rides the recovered discovery; when the identity read never recovers,
	// GetSystemInfo returns the cached failure at once instead of paying
	// another discovery timeout.
	var sysInfo *bmc.SystemInfo
	var hwIdentity *quirks.Identity
	client, clientErr := factory.NewClient(bmcConfig)
	if clientErr == nil {
		defer client.Close()
		hwIdentity = readHardwareIdentity(ctx, client, node.Hostname, logger)
		info, infoErr := client.GetSystemInfo(ctx)
		if infoErr == nil {
			sysInfo = info
		} else {
			logger.Debug("bootstrap: system info retrieval failed",
				slog.String("hostname", node.Hostname),
				slog.String("error", infoErr.Error()))
		}
	} else {
		logger.Debug("bootstrap: BMC client unavailable, system info and hardware identity skipped",
			slog.String("hostname", node.Hostname),
			slog.String("error", clientErr.Error()))
	}

	return DiscoveredNode{
		NodeConfig:       *node,
		DiscoveredMACs:   macs,
		SystemInfo:       sysInfo,
		HardwareIdentity: hwIdentity,
		BMCManaged:       true,
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

// readHardwareIdentity asks a BMC client for the identity it resolves its
// own quirk entry from.
//
// DECISION (issue #112): an incomplete identity is PROPAGATED, not refused.
// The alternative — declining to populate the keys unless all three fields
// are present — was rejected because the BMC client resolves its own quirk
// from the same incomplete value. Refusing would put the installed OS on
// quirks.Default() while the BMC side sits on the vendor entry, which is the
// divergence this function exists to prevent, in a new costume. Parity is
// the rule here, not confidence. The cost of that choice is that an
// incomplete identity may select a manufacturer-wide entry where a complete
// one would have selected a board entry, so every incomplete read is logged
// at WARN naming the fields the BMC did not fill — that log is what a deploy
// postmortem needs to explain which quirk a node actually installed against.
//
// The outcomes:
//
//   - Answered and named its hardware: use it.
//   - Answered and named nothing: use the zero identity. That is a
//     definitive "unidentified" — the config resolver writes empty keys and
//     the installed OS resolves quirks.Default(), which is exactly what the
//     BMC side resolves.
//   - Answered but named only part of it — the IPMI path reports a
//     vendor-only identity with a NIL error when the FRU is definitively
//     unavailable, so this arrives looking like success: use it, and warn.
//
// RULE: completeness is checked on the VALUE, never inferred from the error.
// A nil error means the BMC gave a definitive answer, not that the answer
// named anything. Any future refactor that reaches for err to decide whether
// the identity is usable reintroduces the silent case above.
//   - Failed partway, having learned something (vendor from Get Device ID,
//     then a retryable FRU timeout): use the partial identity, and warn.
//   - Failed having learned nothing: nil. Only a failure that learned
//     nothing returns nil. Nothing is written and whatever the operator set
//     by hand stands, because overwriting a hand-pinned identity on a
//     transport hiccup would silently change which board entry the node
//     installs against.
func readHardwareIdentity(ctx context.Context, client bmc.Client, hostname string, logger *slog.Logger) *quirks.Identity {
	id, err := readHardwareIdentityWithRetry(ctx, client, hostname, logger)
	if err != nil {
		if id == (quirks.Identity{}) {
			logger.Debug("bootstrap: hardware identity unreadable, installer keys left as configured",
				slog.String("hostname", hostname),
				slog.String("error", err.Error()))
			return nil
		}
		logIdentity(logger, "bootstrap: hardware identity still partial after retries, staging what the BMC learned",
			hostname, id, slog.String("error", err.Error()))
		return &id
	}
	logIdentity(logger, "bootstrap: resolved node hardware identity", hostname, id)
	return &id
}

// identityReadAttempts and identityRetryDelay bound the re-read below.
// identityRetryDelay is a var so tests do not pay for it.
const identityReadAttempts = 3

var identityRetryDelay = 500 * time.Millisecond

// readHardwareIdentityWithRetry re-reads an identity the client could not
// resolve, because this is the ONE moment the value is frozen into config.
//
// An error from HardwareIdentity means the client did not cache the answer:
// the failure was retryable, and a later BMC operation will try again and may
// then resolve a MORE specific entry — the FRU read that timed out here can
// succeed a second later and name the board. Staging the first partial answer
// without retrying would freeze the installer on the manufacturer-wide entry
// while the BMC side goes on to use the board entry: parity lost, in the one
// direction nothing downstream can correct, because the installer config is
// written once and the BMC client is consulted for the life of the run.
//
// Retrying does not guarantee agreement — the BMC can still recover after the
// config is written — but it removes the case where we had a cheap chance to
// agree and did not take it. Whatever the last attempt learned is returned
// with its error, so a partial answer is still preferable to none.
func readHardwareIdentityWithRetry(ctx context.Context, client bmc.Client, hostname string, logger *slog.Logger) (quirks.Identity, error) {
	// best is the best identity any FAILED attempt produced (see
	// betterIdentity). Attempts are not monotonic: attempt 1 can name the
	// vendor and then attempt 3 fail before learning anything (a dropped
	// session names nothing at all). Overwriting best with that later zero
	// would report "learned nothing" and leave the keys unset — throwing
	// away the vendor we already had, which is the behaviour this function
	// exists to avoid.
	var best quirks.Identity
	var err error
	for attempt := 1; attempt <= identityReadAttempts; attempt++ {
		var id quirks.Identity
		id, err = client.HardwareIdentity(ctx)
		if err == nil {
			// A nil error is the client's definitive answer, and the value
			// it cached and now resolves its OWN quirk from (see the
			// bmc.Client.HardwareIdentity contract). It is therefore
			// returned as-is even when an earlier failed attempt learned
			// more: staging that richer non-definitive reading instead
			// would put the installed OS on a different entry than the BMC
			// side uses, which is the divergence this whole path exists to
			// prevent. Parity beats richness — the FRU the earlier attempt
			// half-read is now known to be unavailable, not merely slow.
			return id, nil
		}
		if betterIdentity(id, best) {
			best = id
		}
		if attempt == identityReadAttempts {
			break
		}
		logger.Debug("bootstrap: hardware identity read failed, retrying before staging",
			slog.String("hostname", hostname),
			slog.Int("attempt", attempt),
			slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return best, err
		case <-time.After(identityRetryDelay):
		}
	}
	return best, err
}

// betterIdentity reports whether the candidate a should replace the best
// identity b seen so far.
//
// Quirk specificity decides first, because the staged identity's only job is
// to resolve the same quirk the BMC client will resolve. Counting populated
// fields cannot do that: a Supermicro X10 that answers
// {Manufacturer, Model:"Super Server"} on one attempt and
// {Manufacturer, PartNumber:"SYS-5018D-FN8T-AS001"} on the next leaves both
// answers one field short, yet only the second reaches the supermicro/x10sdv
// entry — the first reaches the manufacturer-wide supermicro entry. Keeping
// the first because it arrived earlier stages the wrong quirk, and the
// installer config is written once.
//
// Field count breaks the tie between identities of equal specificity, where
// the extra field is the one that could still matter to a future registry
// entry, or to a human reading the staged config.
func betterIdentity(a, b quirks.Identity) bool {
	if quirks.MoreSpecific(a, b) {
		return true
	}
	if quirks.MoreSpecific(b, a) {
		return false
	}
	return len(identityFieldsMissing(a)) < len(identityFieldsMissing(b))
}

// identityFieldsMissing names the quirk-matching fields the BMC left empty,
// in the order quirks.ResolveIdentity considers them. Empty when the BMC
// filled all three.
//
// A field is "empty" by the same measure matching uses: quirk resolution
// trims before comparing, so a field a BMC padded with spaces matches
// nothing and is missing here too. FRU data is space-padded often enough
// that counting such a field as present would report an identity as
// complete at INFO while it resolves as if the field were absent.
func identityFieldsMissing(id quirks.Identity) []string {
	var missing []string
	for _, f := range []struct {
		name  string
		value string
	}{
		{"manufacturer", id.Manufacturer},
		{"model", id.Model},
		{"part-number", id.PartNumber},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// logIdentity records a captured hardware identity, at INFO when the BMC
// named all three fields and at WARN when it did not.
//
// The WARN is the point of the exercise: an identity missing model AND part
// number can only ever reach a manufacturer-wide entry, never a
// board-specific one, and nothing downstream will say so — the installed OS
// simply resolves a different quirk than a fully-identified node would, and
// the difference shows up as behaviour on a console rather than as an error.
// Naming the missing fields at the point of capture is what makes that
// explicable afterwards.
func logIdentity(logger *slog.Logger, msg, hostname string, id quirks.Identity, extra ...slog.Attr) {
	quirk := quirks.ResolveIdentity(id)
	attrs := []slog.Attr{
		slog.String("hostname", hostname),
		slog.String("quirk", quirk.Key),
		slog.String("manufacturer", id.Manufacturer),
		slog.String("model", id.Model),
		slog.String("part_number", id.PartNumber),
	}
	attrs = append(attrs, extra...)

	// Completeness is checked on the value, never inferred from the error:
	// a vendor-only identity arrives here with a nil error.
	missing := identityFieldsMissing(id)
	if len(missing) == 0 {
		logger.LogAttrs(context.Background(), slog.LevelInfo, msg, attrs...)
		return
	}
	attrs = append(attrs,
		slog.String("missing", strings.Join(missing, ",")),
		// A board entry needs BOTH a manufacturer and something
		// board-shaped to match on. The manufacturer is not optional:
		// every registry entry requires it, so an identity naming a model
		// or part number but no vendor resolves Default() — verified
		// against the registry, not assumed. Reporting reachable=true
		// there would misdirect the postmortem this line exists for.
		slog.Bool("board_entry_reachable",
			id.Manufacturer != "" && (id.Model != "" || id.PartNumber != "")))
	logger.LogAttrs(context.Background(), slog.LevelWarn,
		msg+" (incomplete: quirk selection may differ from a fully-identified node)", attrs...)
}
