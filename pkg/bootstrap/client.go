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

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fetchFunc is the function type used for map-based strategy dispatch.
type fetchFunc func(ctx context.Context) ([]byte, error)

// Client performs trust bootstrap by fetching a CA certificate bundle from a
// remote server using a configured strategy (DANE, Noise, SPKI, or auto).
type Client struct {
	config   *ClientConfig
	logger   *logging.Logger
	handlers map[string]fetchFunc
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

	c := &Client{
		config: config,
		logger: logger,
	}

	c.handlers = map[string]fetchFunc{
		StrategyDANE:     c.fetchDANE,
		StrategyNoise:    c.fetchNoise,
		StrategySPKI:     c.fetchSPKI,
		StrategyEmbedded: c.fetchEmbedded,
		StrategyAuto:     c.fetchAuto,
	}

	return c, nil
}

// FetchCABundle fetches the CA bundle using the configured strategy. It returns
// the PEM-encoded certificate chain bytes. For the embedded strategy, it returns
// nil (trust comes from the ISO-embedded CA bundle, no fetch needed).
func (c *Client) FetchCABundle(ctx context.Context) ([]byte, error) {
	handler, ok := c.handlers[c.config.Strategy]
	if !ok {
		return nil, &ErrStrategyNotSupported{Strategy: c.config.Strategy}
	}

	c.logger.Infof("Bootstrap: fetching CA bundle using strategy %s", c.config.Strategy)

	bundlePEM, err := handler(ctx)
	if err != nil {
		return nil, &ErrBootstrapFetchFailed{
			Strategy: c.config.Strategy,
			Cause:    err,
		}
	}

	return bundlePEM, nil
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

// fetchDANE fetches the CA bundle using DANE/TLSA DNS verification.
func (c *Client) fetchDANE(ctx context.Context) ([]byte, error) {
	bootstrapper, err := truststrap.NewDANEBootstrapper(&truststrap.DANEConfig{
		ServerURL:      c.config.ServerURL,
		Hostname:       c.config.Hostname,
		DNSServer:      c.config.DNSServer,
		ConnectTimeout: c.config.PerMethodTimeout,
		Logger:         c.logger.Slog(),
		BundlePath:     c.config.BundlePath,
	})
	if err != nil {
		return nil, err
	}
	defer bootstrapper.Close()

	resp, err := bootstrapper.FetchCABundle(ctx, nil)
	if err != nil {
		return nil, err
	}

	return resp.BundlePEM, nil
}

// fetchNoise fetches the CA bundle using the Noise_NK protocol.
func (c *Client) fetchNoise(ctx context.Context) ([]byte, error) {
	if c.config.Noise == nil {
		return nil, &ErrInvalidConfig{
			Field:  "noise",
			Reason: "noise configuration is required for noise strategy",
		}
	}

	bootstrapper, err := truststrap.NewNoiseBootstrapper(&truststrap.NoiseConfig{
		ServerAddr:       c.config.Noise.ServerAddr,
		ServerStaticKey:  c.config.Noise.ServerStaticKey,
		ConnectTimeout:   c.config.PerMethodTimeout,
		OperationTimeout: c.config.PerMethodTimeout,
		Logger:           c.logger.Slog(),
	})
	if err != nil {
		return nil, err
	}
	defer bootstrapper.Close()

	resp, err := bootstrapper.FetchCABundle(ctx, nil)
	if err != nil {
		return nil, err
	}

	return resp.BundlePEM, nil
}

// fetchSPKI fetches the CA bundle using SPKI-pinned TLS.
func (c *Client) fetchSPKI(ctx context.Context) ([]byte, error) {
	if c.config.SPKI == nil {
		return nil, &ErrInvalidConfig{
			Field:  "spki",
			Reason: "SPKI configuration is required for spki strategy",
		}
	}

	bootstrapper, err := truststrap.NewSPKIBootstrapper(&truststrap.SPKIConfig{
		ServerURL:      c.config.ServerURL,
		SPKIPinSHA256:  c.config.SPKI.Pin,
		ConnectTimeout: c.config.PerMethodTimeout,
		Logger:         c.logger.Slog(),
		BundlePath:     c.config.BundlePath,
	})
	if err != nil {
		return nil, err
	}
	defer bootstrapper.Close()

	resp, err := bootstrapper.FetchCABundle(ctx, nil)
	if err != nil {
		return nil, err
	}

	return resp.BundlePEM, nil
}

// fetchEmbedded returns nil for the embedded strategy since trust comes from
// the ISO-embedded CA bundle and no network fetch is needed.
func (c *Client) fetchEmbedded(_ context.Context) ([]byte, error) {
	return nil, nil
}

// fetchAuto tries multiple bootstrap methods in priority order using the
// AutoBootstrapper from go-truststrap.
func (c *Client) fetchAuto(ctx context.Context) ([]byte, error) {
	autoCfg := &truststrap.AutoConfig{
		PerMethodTimeout: c.config.PerMethodTimeout,
		Logger:           c.logger.Slog(),
	}

	// Configure DANE if DNS server is available.
	if c.config.DNSServer != "" {
		autoCfg.DANE = &truststrap.DANEConfig{
			ServerURL:      c.config.ServerURL,
			Hostname:       c.config.Hostname,
			DNSServer:      c.config.DNSServer,
			ConnectTimeout: c.config.PerMethodTimeout,
			Logger:         c.logger.Slog(),
			BundlePath:     c.config.BundlePath,
		}
	}

	// Configure Noise if noise config is available.
	if c.config.Noise != nil && c.config.Noise.ServerStaticKey != "" {
		autoCfg.Noise = &truststrap.NoiseConfig{
			ServerAddr:       c.config.Noise.ServerAddr,
			ServerStaticKey:  c.config.Noise.ServerStaticKey,
			ConnectTimeout:   c.config.PerMethodTimeout,
			OperationTimeout: c.config.PerMethodTimeout,
			Logger:           c.logger.Slog(),
		}
	}

	// Configure SPKI if pin is available.
	if c.config.SPKI != nil && c.config.SPKI.Pin != "" {
		autoCfg.SPKI = &truststrap.SPKIConfig{
			ServerURL:      c.config.ServerURL,
			SPKIPinSHA256:  c.config.SPKI.Pin,
			ConnectTimeout: c.config.PerMethodTimeout,
			Logger:         c.logger.Slog(),
			BundlePath:     c.config.BundlePath,
		}
	}

	resp, err := truststrap.AutoFetch(ctx, autoCfg)
	if err != nil {
		return nil, err
	}

	return resp.BundlePEM, nil
}
