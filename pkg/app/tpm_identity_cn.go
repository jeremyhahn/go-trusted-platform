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
// IDevID derives its CN from the hostname when the operator did not set one,
// which is what makes certificates and attestation directories
// self-describing on a fleet.
//
// # The IAK is deliberately left alone — this is an interim, see #74
//
// go-xkms `IAKAttributes()` assigns `KeyAttributes.CN` ONLY inside its
// empty-CN fallback (`"default-device-id"`); a configured CN is never
// assigned, so the attributes reach the certificate store with an empty CN
// and the store rejects them. That is fatal on every boot, before the daemon
// can serve, and it is not recoverable at this layer: on the
// certificate-store path — `IAK.CertHandle == 0`, which is what every shipped
// config uses, since none sets an `iak.cert-handle` — the write
// (`ProvisionIAKCert`) and the read (`IAKCertificate`) derive the storage key
// from those same attributes, so a CN that cannot be written also cannot be
// read back. `IDevIDAttributes()` assigns unconditionally, so IDevID never
// had this problem — it has its own, unrelated one (#80: the NV index is
// defined as a counter, so its cert-handle is cleared and it uses the
// certificate store too).
//
// Until go-xkms#137 lands, the IAK certificate is therefore stored under the
// upstream default. An explicitly configured IAK CN is CLEARED rather than
// passed through, because passing it through is precisely the fatal — there
// is no value this layer can supply that upstream will honour. The warning
// makes the override visible rather than silent.
//
// When the upstream fix is adopted, delete the IAK branch below and restore
// the hostname derivation. Tracked as #78, which also covers migrating
// nodes already provisioned under the interim.
func applyTPMIdentityCNs(cfg *xkmssdk.TPMConfig, hostname string, logger *logging.Logger) {
	if cfg == nil {
		return
	}

	if cfg.IAK != nil && cfg.IAK.CN != "" {
		logger.Warn(
			"ignoring the configured IAK common name: go-xkms discards it and the "+
				"certificate store then rejects the empty result, which is fatal at "+
				"startup (go-xkms#137). The IAK certificate is stored under the "+
				"upstream default until that fix is adopted.",
			"ignored_cn", cfg.IAK.CN)
		cfg.IAK.CN = ""
	}

	// Unlike the IAK, IDevID has no upstream default: `IDevIDAttributes()`
	// assigns `config.IDevID.CN` unconditionally, so whatever is left here
	// is what the identity is stored under. A bare "-idevid" would be a
	// meaningless name shared by every affected node, so an unknown
	// hostname leaves the CN empty and fails loudly at the point of use
	// rather than provisioning a stub identity. In practice this is
	// unreachable: App.Hostname is filled from os.Hostname() during bring-up.
	if cfg.IDevID != nil && cfg.IDevID.CN == "" && hostname != "" {
		cfg.IDevID.CN = hostname + "-idevid"
		logger.Info("Set IDevID CN from hostname", "cn", cfg.IDevID.CN)
	}
}
