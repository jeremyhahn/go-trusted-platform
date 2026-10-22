package app

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
)

// TPM ownership (docs/tpm/engineering.md §4 item 5).
//
// On its first start on an unowned TPM, platformd creates the
// owner-hierarchy keys under the empty auth a fresh TPM ships with, then
// takes ownership (pkg/tpmowner). Every later start finds the TPM owned and
// proves the SO PIN.

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
func (app *App) applyTPMHierarchyAuth(soPIN xkmssdk.Password) (tpmowner.HierarchyAuthState, error) {
	state, err := tpmowner.ReadHierarchyAuthState(app.TPM.Transport())
	if err != nil {
		return state, err
	}
	if app.TPMConfig.SSRK == nil {
		app.TPMConfig.SSRK = &xkmssdk.SRKConfig{}
	}
	if app.TPMConfig.EK == nil {
		app.TPMConfig.EK = &xkmssdk.EKConfig{}
	}
	app.TPMConfig.SSRK.HierarchyAuth = hierarchyAuthFor(state.OwnerAuthSet, soPIN)
	app.TPMConfig.EK.HierarchyAuth = hierarchyAuthFor(state.EndorsementAuthSet, soPIN)
	return state, nil
}

// prepareOwnerHierarchy applies the TPM's hierarchy auth state before the
// Platform KeyStore is opened. On an owned TPM it proves the SO PIN is the
// owner auth, so a wrong SO PIN fails here with
// tpmowner.OwnerAuthRejectedError instead of a bare TPM_RC_BAD_AUTH from a
// later owner-authorized command. It reports whether ownership is still to
// be taken.
func (app *App) prepareOwnerHierarchy(soPIN xkmssdk.Password) (bool, error) {
	state, err := app.applyTPMHierarchyAuth(soPIN)
	if err != nil {
		return false, err
	}
	if !state.OwnerAuthSet {
		return true, nil
	}
	return false, tpmowner.VerifyOwnerAuth(app.TPM.Transport(), soPIN)
}

// takeTPMOwnership sets the owner hierarchy auth from empty to the SO PIN.
// The endorsement and lockout auth are left as they are.
func (app *App) takeTPMOwnership(soPIN xkmssdk.Password) error {
	if err := tpmowner.TakeOwnership(app.TPM, soPIN); err != nil {
		return err
	}
	app.TPMConfig.SSRK.HierarchyAuth = string(soPIN.Bytes())
	app.Logger.Info("TPM ownership taken: owner hierarchy auth set to the SO PIN")
	return nil
}
