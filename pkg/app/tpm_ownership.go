package app

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
)

// TPM ownership (docs/tpm/engineering.md §4 item 5).
//
// On an installed node firstboot takes ownership (pkg/firstboot) with the SO
// PIN platformd resolves, so platformd's first start already finds the TPM
// owned and proves that SO PIN, as every later start does. platformd takes
// ownership itself (pkg/tpmowner) only on a TPM it finds unowned, a node
// firstboot did not provision or one whose TPM was cleared: it creates the
// owner-hierarchy keys under the empty auth, then sets the owner auth to the
// SO PIN.

// hierarchyAuthFor returns the auth a hierarchy currently holds: the SO PIN
// once its authSet bit is set, empty before.
func hierarchyAuthFor(authSet bool, soPIN xkmssdk.Password) (*xkmstypes.SecretValue, error) {
	if !authSet {
		return nil, nil
	}
	return xkmstypes.NewLiteralSecretValue(soPIN.Bytes())
}

// hierarchyAuthBytes returns a copy of a hierarchy auth secret, nil when it is unset or empty.
func hierarchyAuthBytes(auth *xkmstypes.SecretValue) ([]byte, error) {
	if auth == nil {
		return nil, nil
	}
	var out []byte
	err := auth.WithBytes(func(b []byte) error {
		if len(b) > 0 {
			out = append([]byte(nil), b...)
		}
		return nil
	})
	return out, err
}

// hierarchyAuthSet reports whether a hierarchy auth secret holds a non-empty value.
func hierarchyAuthSet(auth *xkmstypes.SecretValue) (bool, error) {
	if auth == nil {
		return false, nil
	}
	set := false
	err := auth.WithBytes(func(b []byte) error {
		set = len(b) > 0
		return nil
	})
	return set, err
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
	ownerAuth, err := hierarchyAuthFor(state.OwnerAuthSet, soPIN)
	if err != nil {
		return state, err
	}
	endorsementAuth, err := hierarchyAuthFor(state.EndorsementAuthSet, soPIN)
	if err != nil {
		return state, err
	}
	app.TPMConfig.SSRK.HierarchyAuth = ownerAuth
	app.TPMConfig.EK.HierarchyAuth = endorsementAuth
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
	ownerAuth, err := hierarchyAuthFor(true, soPIN)
	if err != nil {
		return err
	}
	app.TPMConfig.SSRK.HierarchyAuth = ownerAuth
	app.Logger.Info("TPM ownership taken: owner hierarchy auth set to the SO PIN")
	return nil
}
