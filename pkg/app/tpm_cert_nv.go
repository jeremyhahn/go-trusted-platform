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

// applyCertHandleNVInterim routes TPM identity certificate persistence away
// from NVRAM and into the platform certificate store, before the TPM module
// is constructed from this config.
//
// # Why — this is an interim, see #80
//
// go-xkms `writeCertToNVRAM` defines its NV index with
// `NT: tpm2.TPMNT(0x01)` — **TPM_NT_COUNTER**. A counter index accepts a
// data size of exactly 8 bytes, so the TPM rejects every certificate-sized
// define with `TPM_RC_SIZE` on parameter 2. Certificate storage requires
// TPM_NT_ORDINARY (0x00). Measured against the reference simulator:
// counter/1500 fails, counter/8 succeeds, ordinary/1500 succeeds, and
// ordinary only fails above TPM_PT_NV_INDEX_MAX (2048 here).
//
// The failure is therefore NOT about certificate size and NOT about
// chunking — the write loop already chunks correctly against
// TPM_PT_NV_BUFFER_MAX. Any configured cert handle makes that identity's
// persistence fail on every boot, fatally, before the daemon can serve.
//
// Both identities are covered because `writeCertToNVRAM` is shared:
// `ProvisionIDevIDCert` reaches it whenever `idevid.cert-handle` is set
// (which every shipped template does — this is the live failure), and
// `ProvisionIAKCert` reaches it identically whenever `iak.cert-handle` is
// set (which no shipped template does today — a latent trap for the next
// configuration that sets one).
//
// Clearing the handle is what makes the path work rather than merely fail
// differently: for each identity the Provision and read accessors both
// branch on `CertHandle == 0`, so zero sends the write AND the read to the
// certificate store together. That store is already constructed on every
// boot precisely as the NVRAM fallback, so nothing new is introduced here.
//
// Fixed upstream by go-xkms#138. When that fix is adopted, delete this
// function and its call site so configured handles are honoured again;
// #81 tracks it, including migrating nodes provisioned under the interim
// and the separate TPM_PT_NV_INDEX_MAX size ceiling that NVRAM imposes and
// the certificate store does not.
func applyCertHandleNVInterim(cfg *xkmssdk.TPMConfig, logger *logging.Logger) {
	if cfg == nil {
		return
	}

	// The message is a CONSTANT and the identity is a structured field, so
	// the phrase stays greppable. It previously read "ignoring the
	// configured <identity> cert-handle", which meant the obvious search —
	// the whole point of emitting a warning an operator is meant to find —
	// matched nothing (#94).
	warn := func(identity string, handle uint32) {
		logger.Warn(
			"ignoring the configured cert-handle: go-xkms defines the NV index as a "+
				"counter, so the TPM rejects every certificate-sized write with TPM_RC_SIZE, "+
				"which is fatal at startup (go-xkms#138). The certificate is stored in the "+
				"platform certificate store until that fix is adopted.",
			"identity", identity,
			"ignored_cert_handle", handle)
	}

	if cfg.IDevID != nil && cfg.IDevID.CertHandle != 0 {
		warn("IDevID", cfg.IDevID.CertHandle)
		cfg.IDevID.CertHandle = 0
	}

	if cfg.IAK != nil && cfg.IAK.CertHandle != 0 {
		warn("IAK", cfg.IAK.CertHandle)
		cfg.IAK.CertHandle = 0
	}
}
