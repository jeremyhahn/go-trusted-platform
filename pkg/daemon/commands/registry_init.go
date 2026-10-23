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

package commands

import (
	"log/slog"
	"path/filepath"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/registry"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
)

// registryBackends tracks the OCI distribution backend created
// alongside RegistryService so the REST layer's /v2/ router can
// reach the same *Registry instance. daemon.Config is intentionally
// transport-agnostic so this side-channel keeps the *Registry handle
// off the public daemon API while still letting the webserver mount
// /v2/ at the host root.
var registryBackends = map[*daemon.Config]restregistry.OCIDistBackend{}

func registryDistBackend(cfg *daemon.Config) restregistry.OCIDistBackend {
	return registryBackends[cfg]
}

// initRegistryServiceOnConfig stands up the OCI artifact registry
// behind the daemon's RegistryService surface. Failure is non-fatal:
// the daemon continues without a registry, and gRPC/MCP/REST callers
// see a structured "not configured" envelope per the Phase 0.3
// loud-failure pattern.
//
// Storage today is a local file store under <PlatformDir>/registry.
// Cluster-replicated QuicBaaS-backed storage lands when the cluster
// actually needs multi-node image sharing — the Registry interface is
// stable so the backend swap is hidden from callers.
func initRegistryServiceOnConfig(logger *logging.Logger, app *app.App, cfg *daemon.Config) {
	if cfg == nil || app == nil {
		return
	}
	if cfg.RegistryService != nil {
		// Already configured (e.g. by a test harness).
		return
	}
	root := filepath.Join(app.PlatformDir, "registry")
	client, err := registry.NewFileStorageClient(root)
	if err != nil {
		logger.Warnf("registry: file storage unavailable, surface will be dark: %v", err)
		return
	}
	storage, err := registry.NewQuicBaaSStorage(client)
	if err != nil {
		logger.Warnf("registry: storage layer unavailable: %v", err)
		return
	}
	// Phase 5 first ship: the OCI registry is a process-local
	// surface invoked via the in-process daemon, so the registry's
	// own TLS listener / attestation gate aren't load-bearing here —
	// the API gateway and the gRPC TCP listener already enforce
	// mTLS + JWT. Override the defaults to disable both so config
	// validation doesn't reject a setup where TLS.CertFile and
	// AttestationPolicy were never populated.
	cfgReg := registry.DefaultRegistryConfig()
	cfgReg.TLS.Enabled = false
	cfgReg.Storage.Encrypted = false
	cfgReg.Attestation.RequireAttestation = false
	cfgReg.Encryption.EncryptByDefault = false

	// Local KMS backs the image-encryption pipeline. Keys live under
	// <PlatformDir>/registry/keys — operators back this directory up
	// alongside the rest of <PlatformDir>. When the XKMS-backed
	// KMSClient lands, this is the only swap; ImageEncryptor wires
	// against whatever satisfies registry.KMSClient.
	kmsRoot := filepath.Join(root, "keys")
	kms, err := registry.NewLocalKMSClient(kmsRoot)
	if err != nil {
		logger.Warnf("registry: local KMS unavailable: %v", err)
		return
	}
	encryptor, err := registry.NewImageEncryptor(kms)
	if err != nil {
		logger.Warnf("registry: encryptor unavailable: %v", err)
		return
	}

	opts := []registry.RegistryOption{
		registry.WithStorage(storage),
		registry.WithEncryptor(encryptor),
	}
	signer, err := registryManifestSigner(app.QuicBaaSSDKClient())
	if err != nil {
		logger.Warnf("registry: manifest signer unavailable: %v", err)
		return
	}
	if signer != nil {
		opts = append(opts, registry.WithSigner(signer))
	} else {
		logger.Warn("registry: no QuicBaaS SDK client, signed pushes are refused")
	}
	r, err := registry.NewRegistry(cfgReg, slog.Default(), opts...)
	if err != nil {
		logger.Warnf("registry: failed to construct: %v", err)
		return
	}
	cfg.RegistryService = registry.NewGRPCAdapter(r)
	registryBackends[cfg] = r
	logger.Info("registry service wired", "root", root, "kms_root", kmsRoot)
}

// registryManifestSigner builds the registry's manifest signer on the SDK
// KMS: a signed push signs with the SDK KMS key its SigningKeyID names,
// under that key's policies. With no SDK client it returns no signer, and
// the registry refuses a signed push with registry.ErrSigningNotConfigured.
func registryManifestSigner(sdk quicbaassdk.Client) (registry.SigningKMSClient, error) {
	if sdk == nil {
		return nil, nil
	}
	security := sdk.Security()
	signer, err := registry.NewSDKSigner(security.KMS(), security.Crypto())
	if err != nil {
		return nil, err
	}
	return signer, nil
}
