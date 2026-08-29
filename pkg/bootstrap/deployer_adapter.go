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
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"gopkg.in/yaml.v3"
)

// linuxDeployerAdapter bridges the orchestrator's manifest-based Deployer
// interface to the lower-level deployer.LinuxDeployer's DeployConfig-based
// API. The adapter:
//
//  1. Persists the manifest to a tempfile that the deployer can SCP.
//  2. Builds a deployer.DeployConfig from BootstrapConfig.Deployer +
//     RedeployMode + DataDir + ContainerName defaults.
//  3. Honours RedeployMode by calling Verify before Deploy:
//     - RedeployAlways: skip Verify, always redeploy.
//     - RedeployIfStale (default): Verify; redeploy on any error.
//     - RedeployNever: Verify; ANY error fails the phase.
//  4. Cleans up the tempfile.
//
// The adapter is the only place in the bootstrap package that knows how
// to translate platform-level bootstrap config into deployer.DeployConfig.
// All callers (orchestrator, tests, helpers) go through this adapter so
// the translation rules are testable and idempotent.
type linuxDeployerAdapter struct {
	cfg     *DeployerConfig
	backend deployer.Deployer
	logger  *slog.Logger
}

// newLinuxDeployerAdapter constructs an adapter wired to the provided
// LinuxDeployer (or any deployer.Deployer impl).
func newLinuxDeployerAdapter(cfg *DeployerConfig, backend deployer.Deployer, logger *slog.Logger) *linuxDeployerAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &linuxDeployerAdapter{
		cfg:     cfg,
		backend: backend,
		logger:  logger,
	}
}

// Deploy implements bootstrap.Deployer. It persists the manifest, builds
// a DeployConfig, optionally calls Verify per RedeployMode, then invokes
// the backend Deploy.
func (a *linuxDeployerAdapter) Deploy(ctx context.Context, manifest *container.Manifest) error {
	if a.cfg == nil {
		return ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}
	}

	// Persist the manifest to a tempfile the SSH copy can pick up. The
	// deployer doesn't reach back into Go memory — it expects an
	// on-disk file to scp.
	manifestPath, cleanup, err := writeManifestTemp(manifest)
	if err != nil {
		return ErrContainerDeployFailed{Host: a.cfg.Host, Cause: err}
	}
	defer cleanup()

	dc := a.buildDeployConfig(manifestPath)

	switch a.cfg.EffectiveRedeployMode() {
	case RedeployAlways:
		// Skip Verify entirely; treat the host as if no container exists.
		a.logger.Info("bootstrap: deployer: redeploy_mode=always, forcing redeploy",
			slog.String("host", a.cfg.Host))
	case RedeployIfStale:
		if vErr := a.backend.Verify(ctx, dc); vErr == nil {
			a.logger.Info("bootstrap: deployer: existing container matches expected state, skipping redeploy",
				slog.String("host", a.cfg.Host),
				slog.String("container", dc.ContainerName))
			return nil
		} else {
			a.logger.Info("bootstrap: deployer: existing container state stale, redeploying",
				slog.String("host", a.cfg.Host),
				slog.String("reason", vErr.Error()))
		}
	case RedeployNever:
		vErr := a.backend.Verify(ctx, dc)
		if vErr == nil {
			a.logger.Info("bootstrap: deployer: redeploy_mode=never and container matches, skipping deploy",
				slog.String("host", a.cfg.Host))
			return nil
		}
		// Distinguish "not running" from "running but mismatched".
		// not-running is a benign first-run scenario when redeploy_mode is
		// "never" — fall through to Deploy.
		var notRunning deployer.ErrContainerNotRunning
		if errors.As(vErr, &notRunning) {
			a.logger.Info("bootstrap: deployer: no existing container; first deploy permitted under redeploy_mode=never",
				slog.String("host", a.cfg.Host))
		} else {
			return ErrContainerDeployFailed{Host: a.cfg.Host, Cause: vErr}
		}
	}

	if _, err := a.backend.Deploy(ctx, dc); err != nil {
		return ErrContainerDeployFailed{Host: a.cfg.Host, Cause: err}
	}
	return nil
}

// Teardown implements bootstrap.Deployer.
func (a *linuxDeployerAdapter) Teardown(ctx context.Context) error {
	if a.cfg == nil {
		return ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}
	}
	dc := a.buildDeployConfig("" /* no manifest needed for teardown */)
	if err := a.backend.Teardown(ctx, dc); err != nil {
		return ErrContainerTeardownFailed{Host: a.cfg.Host, Cause: err}
	}
	return nil
}

// buildDeployConfig translates the platform-level DeployerConfig into
// the deployer-package DeployConfig.
func (a *linuxDeployerAdapter) buildDeployConfig(manifestPath string) *deployer.DeployConfig {
	dc := &deployer.DeployConfig{
		Target:             deployer.DeployTarget(a.cfg.Target),
		Host:               a.cfg.Host,
		User:               a.cfg.User,
		SSHKeyPath:         expandUserHome(a.cfg.SSHKey),
		KnownHostsPath:     expandUserHome(a.cfg.KnownHostsPath),
		ContainerRuntime:   a.cfg.ContainerRuntime,
		ContainerImage:     a.cfg.ContainerImage,
		ManifestPath:       manifestPath,
		DataDir:            a.cfg.EffectiveDataDir(),
		RedeployMode:       string(a.cfg.EffectiveRedeployMode()),
		BootstrapInterface: a.cfg.BootstrapInterface,
		BootstrapServerIP:  a.cfg.BootstrapServerIP,
		// Effective* rather than the raw fields so the deployer sends the
		// same ports the orchestrator builds its URLs against.
		BootstrapHTTPPort:         a.cfg.EffectiveBootstrapHTTPPort(),
		BootstrapDeviceScriptPort: a.cfg.EffectiveBootstrapDeviceScriptPort(),
		BootstrapDHCPStart:        a.cfg.BootstrapDHCPStart,
		BootstrapDHCPEnd:          a.cfg.BootstrapDHCPEnd,
		BootstrapGateway:          a.cfg.BootstrapGateway,
		BootstrapDNS:              a.cfg.BootstrapDNS,
		BootstrapAPKMirror:        a.cfg.BootstrapAPKMirror,
	}
	dc.ApplyDefaults()
	return dc
}

// writeManifestTemp marshals the manifest to YAML and persists it to a
// tempfile that the deployer can scp. Returns the path and a cleanup
// function the caller must defer.
func writeManifestTemp(manifest *container.Manifest) (string, func(), error) {
	if manifest == nil {
		return "", func() {}, &MessageError{Msg: "manifest is nil"}
	}
	f, err := os.CreateTemp("", "bootstrap-manifest-*.yaml")
	if err != nil {
		return "", func() {}, err
	}
	defer f.Close()
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(manifest); err != nil {
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	if err := enc.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	return f.Name(), cleanup, nil
}

// expandUserHome expands a leading ~ in SSH key paths so DeployConfig
// always receives an absolute path.
func expandUserHome(p string) string {
	if p == "" {
		return p
	}
	if p[0] != '~' {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[1:])
}

// NewLinuxDeployerAdapter is the public constructor used by CLI helpers.
// It builds a LinuxDeployer backend wired to the supplied
// DeployerConfig.
func NewLinuxDeployerAdapter(cfg *DeployerConfig, logger *slog.Logger) (Deployer, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}
	}
	if cfg.Host == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.host"}
	}
	if cfg.User == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.user"}
	}
	if cfg.SSHKey == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.ssh_key"}
	}
	if cfg.ContainerImage == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.container_image"}
	}
	backend := deployer.NewLinuxDeployer(logger)
	return newLinuxDeployerAdapter(cfg, backend, logger), nil
}
