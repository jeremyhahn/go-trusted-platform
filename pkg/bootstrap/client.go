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
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Client performs trust bootstrap by fetching a CA certificate bundle
// from a remote server using a configured strategy (DANE, Noise, SPKI,
// Direct, or Auto).
//
// Mode dispatch lives in xkms/pkg/trust/bootstrap (the canonical
// trust-bootstrap library in the stack) and is reached through the
// QuicBaaS SDK type-alias re-export. Platform does NOT call
// go-truststrap directly per the SDK-consumption invariant documented
// in CLAUDE.md.
type Client struct {
	config *ClientConfig
	logger *logging.Logger
}

// NewClient creates a new bootstrap Client from the given config and logger.
// It validates the config and returns an error if it is invalid.
func NewClient(config *ClientConfig, logger *logging.Logger) (*Client, error) {
	if config == nil {
		return nil, &ErrInvalidConfig{
			Field:  "config",
			Reason: "config is required",
		}
	}
	if logger == nil {
		return nil, ErrNilLogger{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Client{config: config, logger: logger}, nil
}

// FetchCABundle fetches the CA bundle using the configured strategy.
// Returns the PEM-encoded certificate chain bytes. For the embedded
// strategy the caller's ISO-embedded bundle is authoritative, so the
// method returns (nil, nil) without contacting the network.
func (c *Client) FetchCABundle(ctx context.Context) ([]byte, error) {
	if c.config.Strategy == StrategyEmbedded {
		return nil, nil
	}

	mode, err := strategyToMode(c.config.Strategy)
	if err != nil {
		return nil, err
	}

	cfg, err := c.buildBootstrapConfig(mode)
	if err != nil {
		return nil, err
	}

	c.logger.Infof("Bootstrap: fetching CA bundle using strategy %s", c.config.Strategy)

	bundle, err := bootstrap.Fetch(ctx, cfg)
	if err != nil {
		return nil, &ErrBootstrapFetchFailed{
			Strategy: c.config.Strategy,
			Cause:    err,
		}
	}
	return bundle.PEM, nil
}

// InstallToSystemTrust writes the PEM-encoded CA bundle to the given certificate
// path. The caller is responsible for running OS-specific trust store update
// commands (e.g., update-ca-certificates) afterward.
func (c *Client) InstallToSystemTrust(bundlePEM []byte, certPath string) error {
	if len(bundlePEM) == 0 {
		return ErrCABundleEmpty{}
	}

	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ErrWriteFailed{
			Path: dir,
			Err:  err,
		}
	}

	if err := os.WriteFile(certPath, bundlePEM, 0644); err != nil {
		return &ErrWriteFailed{
			Path: certPath,
			Err:  err,
		}
	}

	c.logger.Infof("Bootstrap: CA bundle installed to %s", certPath)
	return nil
}

// strategyToMode maps platform's strategy constants onto the
// canonical bootstrap.Mode values the library consumes. Embedded is
// handled by the caller (no library call needed) and is therefore
// rejected here as an unsupported mode.
func strategyToMode(strategy string) (bootstrap.Mode, error) {
	switch strategy {
	case StrategyDANE:
		return bootstrap.ModeDANE, nil
	case StrategyNoise:
		return bootstrap.ModeNoise, nil
	case StrategySPKI:
		return bootstrap.ModeSPKI, nil
	case StrategyAuto:
		return bootstrap.ModeAuto, nil
	default:
		return "", &ErrStrategyNotSupported{Strategy: strategy}
	}
}

// buildBootstrapConfig projects platform's ClientConfig onto the
// canonical bootstrap.Config shape. Per-mode sub-configs are
// populated only when the relevant inputs are present so ModeAuto
// silently skips unconfigured methods.
func (c *Client) buildBootstrapConfig(mode bootstrap.Mode) (bootstrap.Config, error) {
	cfg := bootstrap.Config{
		Mode:             mode,
		ServerURL:        c.config.ServerURL,
		BundlePath:       c.config.BundlePath,
		PerMethodTimeout: c.config.PerMethodTimeout,
		Logger:           c.logger.Slog(),
	}

	switch mode {
	case bootstrap.ModeDANE:
		cfg.DANE = &bootstrap.DANEConfig{
			Hostname:  c.config.Hostname,
			DNSServer: c.config.DNSServer,
		}
	case bootstrap.ModeNoise:
		if c.config.Noise == nil {
			return bootstrap.Config{}, &ErrInvalidConfig{
				Field:  "noise",
				Reason: "noise configuration is required for noise strategy",
			}
		}
		cfg.Noise = &bootstrap.NoiseConfig{
			ServerAddr:      c.config.Noise.ServerAddr,
			ServerStaticKey: c.config.Noise.ServerStaticKey,
		}
	case bootstrap.ModeSPKI:
		if c.config.SPKI == nil {
			return bootstrap.Config{}, &ErrInvalidConfig{
				Field:  "spki",
				Reason: "SPKI configuration is required for spki strategy",
			}
		}
		cfg.SPKI = &bootstrap.SPKIConfig{Pin: c.config.SPKI.Pin}
	case bootstrap.ModeAuto:
		if c.config.DNSServer != "" {
			cfg.DANE = &bootstrap.DANEConfig{
				Hostname:  c.config.Hostname,
				DNSServer: c.config.DNSServer,
			}
		}
		if c.config.Noise != nil && c.config.Noise.ServerStaticKey != "" {
			cfg.Noise = &bootstrap.NoiseConfig{
				ServerAddr:      c.config.Noise.ServerAddr,
				ServerStaticKey: c.config.Noise.ServerStaticKey,
			}
		}
		if c.config.SPKI != nil && c.config.SPKI.Pin != "" {
			cfg.SPKI = &bootstrap.SPKIConfig{Pin: c.config.SPKI.Pin}
		}
	}
	return cfg, nil
}
