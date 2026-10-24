// Package tpmowner holds TPM ownership: the owner hierarchy auth set to the
// SO PIN (docs/tpm/engineering.md §4 item 5). Firstboot and platformd both
// reach the TPM through it, so the two agree on how ownership is read, taken
// and proven.
//
// A fresh TPM, hardware or swtpm, ships with empty owner, endorsement and
// lockout auth. Whoever provisions it first creates the owner-hierarchy keys
// under that empty auth and then takes ownership: TPM2_HierarchyChangeAuth
// (TPM 2.0 Part 3 §24.8) sets the owner auth to the SO PIN. The TPM records
// that it did in TPMA_PERMANENT.ownerAuthSet, which survives reboot and is
// cleared only by TPM2_Clear, so every later start reads the bit instead of
// keeping a flag of its own, and presents the SO PIN. The endorsement and
// lockout auth are never changed here.
package tpmowner

import (
	"errors"
	"fmt"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

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
	return fmt.Sprintf("tpmowner: failed to read TPMA_PERMANENT from the TPM: %v", e.Cause)
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
	return fmt.Sprintf("tpmowner: the TPM owner hierarchy rejected the SO PIN: %v", e.Cause)
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
	return fmt.Sprintf("tpmowner: failed to check the TPM owner hierarchy auth: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *OwnerAuthProbeError) Unwrap() error { return e.Cause }

// TPMOwnershipError is returned when TPM2_HierarchyChangeAuth fails to set
// the owner hierarchy auth to the SO PIN.
type TPMOwnershipError struct {
	Cause error
}

// Error returns the error message.
func (e *TPMOwnershipError) Error() string {
	return fmt.Sprintf("tpmowner: failed to take TPM ownership (owner hierarchy auth to the SO PIN): %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *TPMOwnershipError) Unwrap() error { return e.Cause }

// OwnerAuthReleaseError is returned when TPM2_HierarchyChangeAuth fails to
// return a proven owner auth to empty before the keys are recreated.
type OwnerAuthReleaseError struct {
	Cause error
}

// Error returns the error message.
func (e *OwnerAuthReleaseError) Error() string {
	return fmt.Sprintf("tpmowner: failed to return the TPM owner hierarchy auth to empty: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *OwnerAuthReleaseError) Unwrap() error { return e.Cause }

// Module is the part of the SDK TPM ownership needs. The quicbaas
// sdk/go/xkms TrustedPlatformModule satisfies it.
type Module interface {
	Transport() transport.TPM
	SetHierarchyAuth(oldSecret, newSecret xkmssdk.Password, hierarchy *libtpm2.TPMHandle) error
	Config() *xkmssdk.TPMConfig
}

// HierarchyAuthState is the TPM's own record of which hierarchies carry a
// non-empty auth.
type HierarchyAuthState struct {
	OwnerAuthSet       bool
	EndorsementAuthSet bool
}

// ReadHierarchyAuthState reads TPMA_PERMANENT with
// TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT) (TPM 2.0 Part 3
// §30.2) on the SDK TPM's transport.
func ReadHierarchyAuthState(tpm transport.TPM) (HierarchyAuthState, error) {
	rsp, err := libtpm2.GetCapability{
		Capability:    libtpm2.TPMCapTPMProperties,
		Property:      uint32(libtpm2.TPMPTPermanent),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return HierarchyAuthState{}, &TPMPermanentReadError{Cause: err}
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return HierarchyAuthState{}, &TPMPermanentReadError{Cause: err}
	}
	for _, prop := range props.TPMProperty {
		if prop.Property == libtpm2.TPMPTPermanent {
			return HierarchyAuthState{
				OwnerAuthSet:       prop.Value&tpmaPermanentOwnerAuthSet != 0,
				EndorsementAuthSet: prop.Value&tpmaPermanentEndorsementAuthSet != 0,
			}, nil
		}
	}
	return HierarchyAuthState{}, &TPMPermanentReadError{Cause: ErrTPMPermanentNotReported}
}

// VerifyOwnerAuth authorizes the owner hierarchy with the SO PIN in a
// TPM2_CreatePrimary (TPM 2.0 Part 3 §24.1) and flushes the transient key.
// Only the lockout hierarchy is subject to dictionary-attack protection, so
// a wrong PIN costs no lockout.
func VerifyOwnerAuth(tpm transport.TPM, soPIN xkmssdk.Password) error {
	rsp, err := libtpm2.CreatePrimary{
		PrimaryHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMRHOwner,
			Auth:   libtpm2.PasswordAuth(soPIN.Bytes()),
		},
		InPublic: libtpm2.New2B(libtpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		if errors.Is(err, libtpm2.TPMRCBadAuth) || errors.Is(err, libtpm2.TPMRCAuthFail) {
			return &OwnerAuthRejectedError{Cause: err}
		}
		return &OwnerAuthProbeError{Cause: err}
	}
	if _, err := (libtpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(tpm); err != nil {
		return &OwnerAuthProbeError{Cause: err}
	}
	return nil
}

// TakeOwnership sets the owner hierarchy auth from empty to the SO PIN with
// TPM2_HierarchyChangeAuth (TPM 2.0 Part 3 §24.8), which also sets
// TPMA_PERMANENT.ownerAuthSet, and points the SDK TPM's owner (SSRK)
// hierarchy auth at it so later owner authorizations present the SO PIN.
// The endorsement and lockout auth are left as they are.
func TakeOwnership(tpm Module, soPIN xkmssdk.Password) error {
	owner := libtpm2.TPMRHOwner
	if err := tpm.SetHierarchyAuth(nil, soPIN, &owner); err != nil {
		return &TPMOwnershipError{Cause: err}
	}
	presentOwnerAuth(tpm.Config(), soPIN)
	return nil
}

// presentOwnerAuth points the SDK TPM's owner (SSRK) hierarchy auth at the
// SO PIN. The SDK TPM reads it through its shared config.
func presentOwnerAuth(cfg *xkmssdk.TPMConfig, soPIN xkmssdk.Password) {
	if cfg.SSRK == nil {
		cfg.SSRK = &xkmssdk.SRKConfig{}
	}
	cfg.SSRK.HierarchyAuth = string(soPIN.Bytes())
}

// Prepare readies the owner hierarchy for a caller that creates the
// owner-hierarchy keys under the empty auth and takes ownership after, as
// firstboot does. On an unowned TPM it changes nothing. On a TPM already
// owned it proves the SO PIN, so a wrong one fails with
// OwnerAuthRejectedError and the TPM is left as it was, then returns the
// owner auth to empty with TPM2_HierarchyChangeAuth (TPM 2.0 Part 3 §24.8):
// the keys are recreated exactly as on a fresh TPM, and no owner auth reaches
// a key-creation command. The endorsement and lockout auth are left as they
// are.
func Prepare(tpm Module, soPIN xkmssdk.Password) error {
	state, err := ReadHierarchyAuthState(tpm.Transport())
	if err != nil {
		return err
	}
	if !state.OwnerAuthSet {
		return nil
	}
	if err := VerifyOwnerAuth(tpm.Transport(), soPIN); err != nil {
		return err
	}
	owner := libtpm2.TPMRHOwner
	if err := tpm.SetHierarchyAuth(soPIN, nil, &owner); err != nil {
		return &OwnerAuthReleaseError{Cause: err}
	}
	if cfg := tpm.Config(); cfg.SSRK != nil {
		cfg.SSRK.HierarchyAuth = ""
	}
	return nil
}
