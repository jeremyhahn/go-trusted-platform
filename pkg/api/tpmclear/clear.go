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

// Package tpmclear contains the single TPM2_Clear entry point shared by
// every daemon transport (gRPC, REST, Unix, QUIC, MCP).
//
// TPM2_Clear (TPM 2.0 Library Part 3 §24.6) sets the owner, endorsement
// and lockout authValues to the Empty Buffer. The TPM's in-memory config
// still holds the hierarchy auth the daemon decided at start (the SO PIN
// once ownership is taken), and CreateSRK, CreateEK and ProvisionOwner
// authorize with it. A transport that clears the TPM without dropping
// that value leaves every later hierarchy command failing with
// TPM_RC_BAD_AUTH until the daemon restarts. Routing every transport
// through Clear here keeps the TPM and the config in step.
package tpmclear

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrTPMUnavailable is returned when no TPM service is wired.
type ErrTPMUnavailable struct{}

func (e ErrTPMUnavailable) Error() string { return "TPM service not available" }

// Clear runs TPM2_Clear with lockoutAuth and, once the TPM has accepted
// it, resets the in-memory owner (SSRK) and endorsement (EK) hierarchy
// auth to empty to match the cleared TPM. A refused Clear changes
// nothing: the TPM kept its auth values, so the config keeps them too.
// The platform hierarchy is untouched by TPM2_Clear, so the Platform
// SRK auth is left as it is.
func Clear(tpm xkmssdk.TrustedPlatformModule, lockoutAuth []byte) error {
	if tpm == nil {
		return ErrTPMUnavailable{}
	}
	if err := tpm.Clear(lockoutAuth); err != nil {
		return err
	}
	resetHierarchyAuth(tpm.Config())
	return nil
}

// resetHierarchyAuth empties the owner and endorsement hierarchy auth
// held in cfg.
func resetHierarchyAuth(cfg *xkmssdk.TPMConfig) {
	if cfg == nil {
		return
	}
	if cfg.SSRK != nil {
		cfg.SSRK.HierarchyAuth = ""
	}
	if cfg.EK != nil {
		cfg.EK.HierarchyAuth = ""
	}
}
