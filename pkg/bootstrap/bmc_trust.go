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

	xkmsbootstrap "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// bootstrapBMCTLSProvider implements bmc.TLSProvider using the platform
// trust resolver's ClassBMC scope. A single instance is shared across all
// BMC connections within one orchestrator run so re-contacted BMCs can be
// verified against their previously captured TOFU pin.
type bootstrapBMCTLSProvider struct {
	resolver trust.Resolver
}

// Compile-time interface check.
var _ bmc.TLSProvider = (*bootstrapBMCTLSProvider)(nil)

// TLSConfig delegates to the trust resolver's ClassBMC scope for the given
// BMC endpoint.
func (p *bootstrapBMCTLSProvider) TLSConfig(ctx context.Context, endpoint string) (*tls.Config, error) {
	return p.resolver.TLSConfig(ctx, trust.ClassBMC, endpoint)
}

// NewBootstrapBMCTLSProvider constructs a run-scoped bmc.TLSProvider backed
// by the platform trust resolver for the ClassBMC scope.
//
// The resolver is constructed from trustCfg (the platform trust:bmc: block,
// merged with any per-node overrides by nodeBMCTrustConfig before calling
// this function). When any node in the run's ClassBMC chain includes the
// tofu strategy, a plain in-memory pin store is wired in automatically.
// The store is process-lifetime only: SPKI pins are public key hashes and
// carry no secret value, so there is no security loss in keeping them only
// in memory for the duration of the platformctl bootstrap run.
//
// Returns nil, nil, nil when trustCfg is nil or when the BMC scope is not
// configured; in that case BuildTLSConfig falls back to system roots with
// TLS 1.2+ minimum. The caller must check for nil before wiring the
// provider into bmc.Config.TLS.
func NewBootstrapBMCTLSProvider(
	trustCfg *trust.Config,
	logger *slog.Logger,
) (bmc.TLSProvider, *xkmsbootstrap.MemoryPinStore, error) {
	if trustCfg == nil {
		return nil, nil, nil
	}
	bmcScope := trustCfg.Scope(trust.ClassBMC)
	if bmcScope == nil {
		return nil, nil, nil
	}

	// Wrap the *slog.Logger in the platform logging.Logger that
	// trust.NewResolver requires.
	platLogger := logging.NewFromSlog(logger)

	opts := []trust.Option{}

	// Wire a MemoryPinStore when the scope's chain includes TOFU. This is
	// the process-lifetime store described in the task specification: pins
	// are plain SPKI hashes (no secret value), so in-memory lifetime is
	// correct for a single platformctl bootstrap run.
	var pinStore *xkmsbootstrap.MemoryPinStore
	if bmcScope.HasStrategy(trust.StrategyTOFU) {
		pinStore = xkmsbootstrap.NewMemoryPinStore()
		opts = append(opts, trust.WithTOFUPinStore(pinStore))
	}

	resolver, err := trust.NewResolver(trustCfg, platLogger, opts...)
	if err != nil {
		return nil, nil, err
	}

	if logger != nil {
		logger.Debug("bootstrap: constructed BMC trust resolver",
			slog.String("strategies", strategiesStr(bmcScope.Strategies)))
	}

	return &bootstrapBMCTLSProvider{resolver: resolver}, pinStore, nil
}

// nodeBMCTrustConfig builds a trust.Config for a single node by merging the
// node's per-node bmc_trust chain and bmc_spki_pin into the provided base
// config. The returned config is a shallow copy — do not mutate it.
//
// Rules:
//   - If the node has no bmc_trust chain, base is returned unchanged.
//   - If the node has a bmc_trust chain, a new BMC ScopeConfig is constructed
//     using the node's chain. Any bmc_spki_pin is placed in SPKI.Pin so the
//     spki strategy can use it without a pinstore lookup.
//   - The base config's Default and Internal scopes are preserved.
func nodeBMCTrustConfig(node *NodeConfig, base *trust.Config) *trust.Config {
	if len(node.BMCTrust) == 0 && node.BMCSPKIPin == "" {
		return base
	}

	// A node may declare an explicit strategy chain (bmc_trust) and/or a
	// bmc_spki_pin. When only a pin is given, default the chain to the spki
	// strategy so the pin is actually consulted rather than silently dropped.
	strategies := node.BMCTrust
	if len(strategies) == 0 {
		strategies = []trust.Strategy{trust.StrategySPKI}
	}

	scope := &trust.ScopeConfig{
		Strategies: append([]trust.Strategy(nil), strategies...),
	}
	if node.BMCSPKIPin != "" {
		scope.SPKI = &trust.SPKIConfig{Pin: node.BMCSPKIPin}
	}

	merged := &trust.Config{}
	if base != nil {
		*merged = *base
	}
	merged.BMC = scope
	return merged
}

// nodeBMCTLSProvider returns the BMC TLS provider to use for a single node.
// When the node declares a bmc_spki_pin or an explicit bmc_trust chain, a
// node-scoped provider is built so the node's own SPKI pin is honored -- each
// BMC presents a distinct (often expired) self-signed cert, so one shared
// provider cannot cover them all. Nodes with no per-node trust use the
// run-shared provider, preserving TOFU pin continuity across re-contacted BMCs.
func (o *Orchestrator) nodeBMCTLSProvider(node *NodeConfig) bmc.TLSProvider {
	if node.BMCSPKIPin == "" && len(node.BMCTrust) == 0 {
		return o.bmcTLSProvider
	}
	provider, _, err := NewBootstrapBMCTLSProvider(nodeBMCTrustConfig(node, o.trustConfig), o.logger)
	if err != nil || provider == nil {
		o.logger.Warn("bootstrap: per-node BMC TLS provider build failed; using run-shared provider",
			slog.String("hostname", node.Hostname),
			slog.Any("error", err))
		return o.bmcTLSProvider
	}
	return provider
}

// strategiesStr formats a strategy slice for log output.
func strategiesStr(strategies []trust.Strategy) string {
	if len(strategies) == 0 {
		return "(none)"
	}
	out := ""
	for i, s := range strategies {
		if i > 0 {
			out += ","
		}
		out += string(s)
	}
	return out
}
