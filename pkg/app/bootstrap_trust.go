// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package app

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// ErrBootstrapTOFUNoSDK is returned when the trust config lists the tofu
// strategy but the QuicBaaS SDK client required for the durable pin store is
// not available. TOFU must never run without pin persistence — a pin that
// cannot be stored cannot be verified on the next connection.
type ErrBootstrapTOFUNoSDK struct{}

// Error implements error.
func (e ErrBootstrapTOFUNoSDK) Error() string {
	return "app: trust config lists the tofu strategy but the QuicBaaS SDK client is not available for the pin store"
}

// ErrBootstrapTOFUPinStore is returned when the qrdb-backed TOFU pin store
// cannot be constructed from the QuicBaaS SDK client.
type ErrBootstrapTOFUPinStore struct {
	Cause error
}

// Error implements error.
func (e ErrBootstrapTOFUPinStore) Error() string {
	return fmt.Sprintf("app: failed to build TOFU pin store: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapTOFUPinStore) Unwrap() error { return e.Cause }

// trustConfigNeedsTOFU reports whether any configured trust class lists the
// tofu strategy. TOFU requires a pin store at resolver construction time, so
// callers use this to decide whether resolver options are mandatory.
func trustConfigNeedsTOFU(cfg *trust.Config) bool {
	if cfg == nil {
		return false
	}
	for _, scope := range []*trust.ScopeConfig{cfg.Default, cfg.BMC, cfg.Internal} {
		if scope == nil {
			continue
		}
		for _, s := range scope.Strategies {
			if s == trust.StrategyTOFU {
				return true
			}
		}
	}
	return false
}

// scopeIsEmbeddedOnly reports whether the scope's strategy chain consists
// solely of the embedded strategy, meaning trust comes from the ISO-embedded
// CA bundle and no runtime fetch is needed.
func scopeIsEmbeddedOnly(scope *trust.ScopeConfig) bool {
	if scope == nil || len(scope.Strategies) == 0 {
		return false
	}
	for _, s := range scope.Strategies {
		if s != trust.StrategyEmbedded {
			return false
		}
	}
	return true
}

// buildTOFUResolverOpts returns the resolver options that wire the
// qrdb-backed TOFU pin store, or nil when TOFU is not listed in the trust
// config or the QuicBaaS SDK client is unavailable. BootstrapTrust treats
// nil-with-TOFU-needed as ErrBootstrapTOFUNoSDK.
func (app *App) buildTOFUResolverOpts() []trust.Option {
	if !trustConfigNeedsTOFU(app.TrustConfig) {
		return nil
	}
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok || dbFactory == nil {
		app.Logger.Warn("trust bootstrap: tofu strategy configured but QuicBaaS factory is not initialized")
		return nil
	}
	sdkClient := dbFactory.SDKClient()
	if sdkClient == nil {
		app.Logger.Warn("trust bootstrap: tofu strategy configured but QuicBaaS SDK client is not available")
		return nil
	}
	pinStore, err := quicbaas.NewTOFUPinStore(sdkClient)
	if err != nil {
		app.Logger.Warn("trust bootstrap: failed to build TOFU pin store",
			"error", ErrBootstrapTOFUPinStore{Cause: err})
		return nil
	}
	return []trust.Option{trust.WithTOFUPinStore(pinStore)}
}
