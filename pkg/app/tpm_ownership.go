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
	"errors"
	"fmt"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// TPM ownership (docs/tpm/engineering.md §4 item 5).
//
// A fresh TPM, hardware or swtpm, ships with empty owner, endorsement and
// lockout auth, and firstboot leaves them empty. Platformd's first
// provisioning creates the owner-hierarchy keys under that empty auth and
// then takes ownership: TPM2_HierarchyChangeAuth (TPM 2.0 Part 3 §24.8) sets
// the owner auth to the SO PIN. The TPM records that it did in
// TPMA_PERMANENT.ownerAuthSet, which survives reboot and is cleared only by
// TPM2_Clear, so every later start reads the bit instead of keeping a flag of
// its own, and presents the SO PIN.

// TPMA_PERMANENT bits, TPM 2.0 Part 2 Structures §8.6. The TPM
// sets a bit when TPM2_HierarchyChangeAuth gives the hierarchy a non-empty
// authValue and clears it on TPM2_Clear.
const (
	tpmaPermanentOwnerAuthSet       uint32 = 1 << 0
	tpmaPermanentEndorsementAuthSet uint32 = 1 << 1
)

// ErrTPMPermanentNotReported is the cause of a TPMPermanentReadError when the
// TPM answers TPM2_GetCapability without the TPM_PT_PERMANENT property.
var ErrTPMPermanentNotReported = errors.New("TPM did not report TPM_PT_PERMANENT")

// TPMPermanentReadError is returned when the TPM's TPMA_PERMANENT attributes
// cannot be read, so whether ownership was taken is unknown.
type TPMPermanentReadError struct {
	Cause error
}

// Error returns the error message.
func (e *TPMPermanentReadError) Error() string {
	return fmt.Sprintf("app: failed to read TPMA_PERMANENT from the TPM: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *TPMPermanentReadError) Unwrap() error { return e.Cause }

// OwnerAuthRejectedError is returned when the TPM owner hierarchy, already
// owned (TPMA_PERMANENT.ownerAuthSet), rejects the SO PIN.
type OwnerAuthRejectedError struct {
	Cause error
}

// Error returns the error message.
func (e *OwnerAuthRejectedError) Error() string {
	return fmt.Sprintf("app: the TPM owner hierarchy rejected the SO PIN: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *OwnerAuthRejectedError) Unwrap() error { return e.Cause }

// OwnerAuthProbeError is returned when the owner-hierarchy auth check fails
// for a reason other than a wrong SO PIN.
type OwnerAuthProbeError struct {
	Cause error
}

// Error returns the error message.
func (e *OwnerAuthProbeError) Error() string {
	return fmt.Sprintf("app: failed to check the TPM owner hierarchy auth: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *OwnerAuthProbeError) Unwrap() error { return e.Cause }

// TPMOwnershipError is returned when TPM2_HierarchyChangeAuth fails to set
// the owner hierarchy auth to the SO PIN on first provisioning.
type TPMOwnershipError struct {
	Cause error
}

// Error returns the error message.
func (e *TPMOwnershipError) Error() string {
	return fmt.Sprintf("app: failed to take TPM ownership (owner hierarchy auth to the SO PIN): %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *TPMOwnershipError) Unwrap() error { return e.Cause }

// tpmHierarchyAuthState is the TPM's own record of which hierarchies carry a
// non-empty auth.
type tpmHierarchyAuthState struct {
	ownerAuthSet       bool
	endorsementAuthSet bool
}

// readTPMHierarchyAuthState reads TPMA_PERMANENT with
// TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT) (TPM 2.0 Part 3
// §30.2) on the SDK TPM's transport.
func readTPMHierarchyAuthState(tpm transport.TPM) (tpmHierarchyAuthState, error) {
	rsp, err := libtpm2.GetCapability{
		Capability:    libtpm2.TPMCapTPMProperties,
		Property:      uint32(libtpm2.TPMPTPermanent),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return tpmHierarchyAuthState{}, &TPMPermanentReadError{Cause: err}
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return tpmHierarchyAuthState{}, &TPMPermanentReadError{Cause: err}
	}
	for _, prop := range props.TPMProperty {
		if prop.Property == libtpm2.TPMPTPermanent {
			return tpmHierarchyAuthState{
				ownerAuthSet:       prop.Value&tpmaPermanentOwnerAuthSet != 0,
				endorsementAuthSet: prop.Value&tpmaPermanentEndorsementAuthSet != 0,
			}, nil
		}
	}
	return tpmHierarchyAuthState{}, &TPMPermanentReadError{Cause: ErrTPMPermanentNotReported}
}

// hierarchyAuthFor returns the auth a hierarchy currently holds: the SO PIN
// once its authSet bit is set, empty before.
func hierarchyAuthFor(authSet bool, soPIN xkmssdk.Password) string {
	if !authSet {
		return ""
	}
	return string(soPIN.Bytes())
}

// applyTPMHierarchyAuth points TPMConfig's owner (SSRK) and endorsement (EK)
// hierarchy auth at what the TPM says each hierarchy holds. The SDK TPM reads
// these fields through its shared config, so every later owner or
// endorsement authorization presents the current auth.
func (app *App) applyTPMHierarchyAuth(soPIN xkmssdk.Password) (tpmHierarchyAuthState, error) {
	state, err := readTPMHierarchyAuthState(app.TPM.Transport())
	if err != nil {
		return state, err
	}
	if app.TPMConfig.SSRK == nil {
		app.TPMConfig.SSRK = &xkmssdk.SRKConfig{}
	}
	if app.TPMConfig.EK == nil {
		app.TPMConfig.EK = &xkmssdk.EKConfig{}
	}
	app.TPMConfig.SSRK.HierarchyAuth = hierarchyAuthFor(state.ownerAuthSet, soPIN)
	app.TPMConfig.EK.HierarchyAuth = hierarchyAuthFor(state.endorsementAuthSet, soPIN)
	return state, nil
}

// prepareOwnerHierarchy applies the TPM's hierarchy auth state before the
// Platform KeyStore is opened. On an owned TPM it proves the SO PIN is the
// owner auth, so a wrong SO PIN fails here with OwnerAuthRejectedError
// instead of a bare TPM_RC_BAD_AUTH from a later owner-authorized command.
// It reports whether ownership is still to be taken.
func (app *App) prepareOwnerHierarchy(soPIN xkmssdk.Password) (bool, error) {
	state, err := app.applyTPMHierarchyAuth(soPIN)
	if err != nil {
		return false, err
	}
	if !state.ownerAuthSet {
		return true, nil
	}
	return false, verifyOwnerAuth(app.TPM.Transport(), soPIN)
}

// verifyOwnerAuth authorizes the owner hierarchy with the SO PIN in a
// TPM2_PolicySecret (TPM 2.0 Part 3 §23.4) against a policy session it
// starts and flushes. The TPM checks the authHandle's authValue before the
// command runs, and the command creates no object, so the probe needs no key
// algorithm: an RSA-only or ECC-only TPM answers it alike. Only the lockout
// hierarchy is subject to dictionary-attack protection, so a wrong PIN costs
// no lockout.
func verifyOwnerAuth(tpm transport.TPM, soPIN xkmssdk.Password) error {
	session, closeSession, err := libtpm2.PolicySession(tpm, libtpm2.TPMAlgSHA256, 16)
	if err != nil {
		return &OwnerAuthProbeError{Cause: err}
	}
	_, err = libtpm2.PolicySecret{
		AuthHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMRHOwner,
			Auth:   libtpm2.PasswordAuth(soPIN.Bytes()),
		},
		PolicySession: session.Handle(),
	}.Execute(tpm)
	closeErr := closeSession()
	if err != nil {
		if errors.Is(err, libtpm2.TPMRCBadAuth) || errors.Is(err, libtpm2.TPMRCAuthFail) {
			return &OwnerAuthRejectedError{Cause: err}
		}
		return &OwnerAuthProbeError{Cause: err}
	}
	if closeErr != nil {
		return &OwnerAuthProbeError{Cause: closeErr}
	}
	return nil
}

// takeTPMOwnership sets the owner hierarchy auth from empty to the SO PIN
// with TPM2_HierarchyChangeAuth (TPM 2.0 Part 3 §24.8), which also sets
// TPMA_PERMANENT.ownerAuthSet. The endorsement and lockout auth are left as
// they are.
func (app *App) takeTPMOwnership(soPIN xkmssdk.Password) error {
	owner := libtpm2.TPMRHOwner
	if err := app.TPM.SetHierarchyAuth(nil, soPIN, &owner); err != nil {
		return &TPMOwnershipError{Cause: err}
	}
	app.TPMConfig.SSRK.HierarchyAuth = string(soPIN.Bytes())
	app.Logger.Info("TPM ownership taken: owner hierarchy auth set to the SO PIN")
	return nil
}
