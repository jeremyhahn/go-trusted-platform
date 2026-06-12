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
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// trustConfigNeedsTOFU
// =============================================================================

func TestTrustConfigNeedsTOFU_NilConfig(t *testing.T) {
	t.Parallel()
	assert.False(t, trustConfigNeedsTOFU(nil))
}

func TestTrustConfigNeedsTOFU_NoTOFUInAnyClass(t *testing.T) {
	t.Parallel()
	cfg := &trust.Config{
		Default: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyDANE, trust.StrategySPKI},
		},
	}
	assert.False(t, trustConfigNeedsTOFU(cfg))
}

func TestTrustConfigNeedsTOFU_TOFUInDefaultClass(t *testing.T) {
	t.Parallel()
	cfg := &trust.Config{
		Default: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyTOFU},
		},
	}
	assert.True(t, trustConfigNeedsTOFU(cfg))
}

func TestTrustConfigNeedsTOFU_TOFUInBMCClass(t *testing.T) {
	t.Parallel()
	cfg := &trust.Config{
		Default: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyEmbedded},
		},
		BMC: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyTOFU},
		},
	}
	assert.True(t, trustConfigNeedsTOFU(cfg))
}

func TestTrustConfigNeedsTOFU_TOFUInInternalClass(t *testing.T) {
	t.Parallel()
	cfg := &trust.Config{
		Internal: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategySPKI, trust.StrategyTOFU},
		},
	}
	assert.True(t, trustConfigNeedsTOFU(cfg))
}

// =============================================================================
// buildTOFUResolverOpts
// =============================================================================

func TestBuildTOFUResolverOpts_TOFUNotNeeded(t *testing.T) {
	t.Parallel()

	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyEmbedded},
			},
		},
		Logger: logging.DefaultLogger(),
	}

	opts := app.buildTOFUResolverOpts()
	assert.Nil(t, opts, "no options should be returned when TOFU is not in the config")
}

func TestBuildTOFUResolverOpts_TOFUNeededButNoFactory(t *testing.T) {
	t.Parallel()

	// daoFactory is nil (never initialized).
	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyTOFU},
				ServerURL:  "https://cp.example.com:8443",
			},
		},
		Logger: logging.DefaultLogger(),
	}

	// buildTOFUResolverOpts returns nil when the factory is not available.
	// BootstrapTrust will then return ErrBootstrapTOFUNoSDK.
	opts := app.buildTOFUResolverOpts()
	assert.Nil(t, opts)
}

// =============================================================================
// BootstrapTrust — TOFU config path
// =============================================================================

// TestBootstrapTrust_NilConfig verifies the function is a no-op when
// TrustConfig is nil.
func TestBootstrapTrust_NilConfig(t *testing.T) {
	t.Parallel()

	app := &App{Logger: logging.DefaultLogger()}
	err := app.BootstrapTrust(context.Background())
	require.NoError(t, err)
}

// TestBootstrapTrust_NoDefaultScope verifies the function is a no-op when
// the default trust scope is not configured.
func TestBootstrapTrust_NoDefaultScope(t *testing.T) {
	t.Parallel()

	app := &App{
		TrustConfig: &trust.Config{}, // all scopes nil
		Logger:      logging.DefaultLogger(),
	}
	err := app.BootstrapTrust(context.Background())
	require.NoError(t, err)
}

// TestBootstrapTrust_EmbeddedOnlySkips verifies that a config with only the
// embedded strategy returns nil without making any network calls.
func TestBootstrapTrust_EmbeddedOnlySkips(t *testing.T) {
	t.Parallel()

	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyEmbedded},
			},
		},
		Logger: logging.DefaultLogger(),
	}
	err := app.BootstrapTrust(context.Background())
	require.NoError(t, err)
}

// TestBootstrapTrust_TOFUListedButNoSDKReturnsTypedError verifies that when
// the trust config lists the tofu strategy but the QuicBaaS SDK client is not
// available (daoFactory is nil), BootstrapTrust returns ErrBootstrapTOFUNoSDK
// rather than silently skipping the strategy or returning a generic error.
func TestBootstrapTrust_TOFUListedButNoSDKReturnsTypedError(t *testing.T) {
	t.Parallel()

	// daoFactory is nil — the SDK client is not available.
	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyTOFU},
				ServerURL:  "https://cp.example.com:8443",
			},
		},
		Logger: logging.DefaultLogger(),
	}

	err := app.BootstrapTrust(context.Background())
	require.Error(t, err)

	var tofuErr ErrBootstrapTOFUNoSDK
	assert.True(t, errors.As(err, &tofuErr), "expected ErrBootstrapTOFUNoSDK, got %T: %v", err, err)
}

// TestBootstrapTrust_TOFUListedInBMCButNoSDKReturnsTypedError verifies that
// when the default class is non-embedded (so the resolver will be constructed)
// and the BMC class lists TOFU, ErrBootstrapTOFUNoSDK is returned when the
// SDK client is unavailable.
func TestBootstrapTrust_TOFUListedInBMCButNoSDKReturnsTypedError(t *testing.T) {
	t.Parallel()

	// Default class is SPKI (non-embedded) so BootstrapTrust will proceed to
	// construct the resolver. The BMC class lists TOFU, which triggers the
	// SDK-required check.
	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategySPKI},
				ServerURL:  "https://cp.example.com:8443",
				SPKI: &trust.SPKIConfig{
					Pin: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
				},
			},
			BMC: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyTOFU},
				ServerURL:  "https://bmc.example.com:443",
			},
		},
		Logger: logging.DefaultLogger(),
	}

	err := app.BootstrapTrust(context.Background())
	require.Error(t, err)
	var tofuErr ErrBootstrapTOFUNoSDK
	assert.True(t, errors.As(err, &tofuErr), "expected ErrBootstrapTOFUNoSDK, got %T: %v", err, err)
}

// TestBootstrapTrust_NonTOFUConfigCallsResolverWithoutPinStore verifies that
// a config without the tofu strategy proceeds to call trust.NewResolver
// normally. The embedded strategy causes an early return, so the test checks
// that no ErrBootstrapTOFUNoSDK is returned — the embedded path exits before
// the resolver is constructed.
func TestBootstrapTrust_NonTOFUConfigDoesNotReturnTOFUError(t *testing.T) {
	t.Parallel()

	// Config with DANE + SPKI but no TOFU, no daoFactory.
	// The resolver will be constructed but then fail to fetch (no network),
	// returning an ErrBootstrapClientInit or ErrBootstrapFetchBundle — NOT
	// ErrBootstrapTOFUNoSDK. This guards the regression: non-TOFU paths must
	// not require an SDK client.
	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyEmbedded},
			},
		},
		Logger: logging.DefaultLogger(),
	}

	err := app.BootstrapTrust(context.Background())
	require.NoError(t, err, "embedded-only config must be a no-op")
	assert.False(t, errors.As(err, &ErrBootstrapTOFUNoSDK{}))
}

// =============================================================================
// Error type tests
// =============================================================================

func TestErrBootstrapTOFUNoSDK_Error(t *testing.T) {
	t.Parallel()
	e := ErrBootstrapTOFUNoSDK{}
	assert.Contains(t, e.Error(), "tofu strategy")
	assert.Contains(t, e.Error(), "QuicBaaS SDK client")
}

func TestErrBootstrapTOFUPinStore_Error(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")
	e := ErrBootstrapTOFUPinStore{Cause: cause}
	assert.Contains(t, e.Error(), "TOFU pin store")
	assert.Contains(t, e.Error(), "connection refused")
	assert.ErrorIs(t, e, cause)
}

func TestErrBootstrapTOFUPinStore_Unwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("root cause")
	e := ErrBootstrapTOFUPinStore{Cause: cause}
	assert.Equal(t, cause, e.Unwrap())
}

// =============================================================================
// InternalCAPool
// =============================================================================

func TestInternalCAPool_NilTrustConfig(t *testing.T) {
	t.Parallel()
	// When TrustConfig is nil, TrustResolver returns nil, and InternalCAPool
	// must return (nil, nil) without error.
	app := &App{}
	pool, err := app.InternalCAPool(context.Background())
	require.NoError(t, err)
	assert.Nil(t, pool)
}

func TestInternalCAPool_InternalClassNotConfigured(t *testing.T) {
	t.Parallel()
	// A TrustConfig with no internal scope must return (nil, nil) without error
	// so existing deployments without the trust: internal YAML block keep working.
	app := &App{
		TrustConfig: &trust.Config{
			Default: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyEmbedded},
			},
		},
		Logger: logging.DefaultLogger(),
	}
	// Must not error even though ClassInternal is unconfigured.
	pool, err := app.InternalCAPool(context.Background())
	require.NoError(t, err)
	assert.Nil(t, pool, "nil pool expected when internal class not configured")
}
