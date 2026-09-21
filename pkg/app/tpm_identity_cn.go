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

package app

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// applyTPMIdentityCNs settles the common names the TPM identity keys are
// stored under, before the TPM module is constructed from this config.
//
// Both identities derive their CN from the hostname when the operator did
// not set one (`<hostname>-iak`, `<hostname>-idevid`), which is what makes
// certificates and attestation directories self-describing on a fleet. An
// operator-configured CN is preserved.
//
// The IAK derivation is the contract #78 restored. go-xkms#137 (adopted
// with go-xkms v0.9.4-alpha) made `IAKAttributes()` honour a configured CN;
// before it, the platform left the IAK CN empty so upstream's
// `default-device-id` fallback applied (#74). That interim is now itself
// the fatal it once avoided: on a fresh provision `CreateIAK` caches
// attributes built straight from the config, and an empty CN reaches the
// certificate store, which rejects it. Nodes provisioned under the interim
// are carried over by migrateInterimIAKCertificate.
//
// A bare "-iak" / "-idevid" would be a meaningless name shared by every
// affected node, so an unknown hostname leaves the CN empty and fails
// loudly at the point of use rather than provisioning a stub identity. In
// practice this is unreachable: App.Hostname is filled from os.Hostname()
// during bring-up.
func applyTPMIdentityCNs(cfg *xkmssdk.TPMConfig, hostname string, logger *logging.Logger) {
	if cfg == nil {
		return
	}
	if cfg.IAK != nil && cfg.IAK.CN == "" && hostname != "" {
		cfg.IAK.CN = hostname + "-iak"
		logger.Info("Set IAK CN from hostname", "cn", cfg.IAK.CN)
	}
	if cfg.IDevID != nil && cfg.IDevID.CN == "" && hostname != "" {
		cfg.IDevID.CN = hostname + "-idevid"
		logger.Info("Set IDevID CN from hostname", "cn", cfg.IDevID.CN)
	}
}
