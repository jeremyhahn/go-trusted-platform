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
// # Why — this is an interim, see #81
//
// go-xkms#138 (the NV index defined as TPM_NT_COUNTER) is fixed at the
// pinned go-xkms: the index is TPM_NT_ORDINARY and a certificate larger than
// TPM_PT_NV_INDEX_MAX is refused before the define. The NV write still cannot
// succeed on a platform TPM, for a second reason: go-xkms `writeCertToNVRAM`
// authorizes TPM2_NV_DefineSpace on the owner hierarchy with an EMPTY
// password, while `provisionTPMHierarchies` sets the owner auth to the SO PIN
// before `provisionPlatformIdentity` provisions the IAK and IDevID
// certificates. Measured against the reference simulator: with empty owner
// auth the IDevID certificate is written and read back; with the owner auth
// set the define fails with TPM_RC_BAD_AUTH. A second provision of the same
// index fails with TPM_RC_NV_DEFINED, because the index is never undefined
// first. Every cached go-xkms tag up to v0.55.0-alpha has the same
// authorization. Honouring a configured handle today would make identity
// provisioning fail on every node, fatally.
//
// Both identities are covered because `writeCertToNVRAM` is shared:
// `ProvisionIDevIDCert` reaches it whenever `idevid.cert-handle` is set
// (which every shipped template does), and `ProvisionIAKCert` reaches it
// identically whenever `iak.cert-handle` is set.
//
// Clearing the handle is what makes the path work rather than merely fail
// differently: for each identity the Provision and read accessors both
// branch on `CertHandle == 0`, so zero sends the write AND the read to the
// certificate store together. That store is already constructed on every
// boot, so nothing new is introduced here.
//
// The EK certificate is not affected: `ProvisionEKCert` authorizes with the
// hierarchy auth it is given, and provisionEKCertificate places it in NV when
// it fits. When go-xkms authorizes the identity NV writes with the owner
// hierarchy auth, delete this function and its call site; #81 tracks it.
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
			"ignoring the configured cert-handle: go-xkms authorizes the identity "+
				"certificate NV define with an empty owner password, so on a TPM the platform "+
				"owns the write fails with TPM_RC_BAD_AUTH, which is fatal at startup (#81). "+
				"The certificate is stored in the platform certificate store.",
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
