package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
)

// SO PIN handoff (docs/tpm/engineering.md §4 item 5).
//
// firstboot takes TPM ownership with the SO PIN platformd uses. When
// platform.so-pin is a kms://...?ensure=true reference there is no KMS to
// read before platformd runs, so firstboot generates the PIN and stages it
// at tpmowner.SOPINHandoffFile. platformd stores it at the reference's KMS
// path before ProcessSecrets resolves the reference, which then finds the
// secret and returns that PIN instead of generating a new one.

// SOPINHandoffError is returned when the SO PIN firstboot staged cannot be
// stored at its KMS path. The staged file is kept on its tmpfs so a restart
// can retry: shredding it would lose the TPM owner auth.
type SOPINHandoffError struct {
	Stage string
	Cause error
}

// Error returns the error message.
func (e *SOPINHandoffError) Error() string {
	return fmt.Sprintf("sopin-handoff: %s: %v", e.Stage, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *SOPINHandoffError) Unwrap() error { return e.Cause }

// ErrSOPINHandoffSecretsUnavailable is the cause of a SOPINHandoffError when
// no SecretsService is available to store the staged SO PIN in.
var ErrSOPINHandoffSecretsUnavailable = errors.New("SecretsService not available")

// ErrSOPINHandoffTPMUnowned is the reason a staged SO PIN is rejected when
// the TPM owner hierarchy has no auth set: firstboot did not take ownership
// with it.
var ErrSOPINHandoffTPMUnowned = errors.New("the TPM owner hierarchy has no auth set")

// ErrSOPINHandoffNoTPM is the cause of a SOPINHandoffError when no TPM is
// open to verify the staged SO PIN against.
var ErrSOPINHandoffNoTPM = errors.New("no TPM to verify the staged SO PIN against")

// SOPINHandoffRejectedError is the reason a staged SO PIN was discarded: it
// differs from the SO PIN already persisted at KMSPath and the TPM did not
// confirm it as the owner auth. The persisted SO PIN is kept. A firstboot
// retry stages such a PIN when its tmpfs handoff is gone and its Prepare
// step was refused by the already owned TPM.
type SOPINHandoffRejectedError struct {
	KMSPath string
	Reason  error
}

// Error returns the error message.
func (e *SOPINHandoffRejectedError) Error() string {
	return fmt.Sprintf("sopin-handoff: staged SO PIN discarded, the SO PIN persisted at %s is kept: %v", e.KMSPath, e.Reason)
}

// Unwrap returns the reason.
func (e *SOPINHandoffRejectedError) Unwrap() error { return e.Reason }

// ownerAuthVerifier proves an SO PIN is the TPM owner hierarchy's auth.
type ownerAuthVerifier func(soPIN xkmssdk.Password) error

// ConsumeSOPINHandoff stores the SO PIN firstboot staged at the KMS path
// platform.so-pin names. It must run after initStores and before
// ProcessSecrets. No staged file is a no-op. With no SO PIN persisted yet
// (first provision) the staged PIN is stored as is: there is no credential
// to lose. A staged PIN that differs from the persisted one replaces it
// only once the TPM confirms it as the owner auth.
func (app *App) ConsumeSOPINHandoff(ctx context.Context) error {
	return app.consumeSOPINHandoff(ctx, app.secureBootSecretStore(), app.verifyOwnerAuthAtHandoff, tpmowner.SOPINHandoffFile)
}

// consumeSOPINHandoff is ConsumeSOPINHandoff against an explicit secret
// store and handoff path. The staged file is shredded once the PIN is stored,
// or when platform.so-pin no longer names a KMS path to store it at.
func (app *App) consumeSOPINHandoff(ctx context.Context, store secretStore, verify ownerAuthVerifier, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return &SOPINHandoffError{Stage: "read " + path, Cause: err}
	}
	defer clear(data)

	var configured string
	if app.PlatformConfig != nil {
		configured = app.PlatformConfig.SOPin
	}
	ref, err := tpmowner.ParseSOPINRef(configured)
	if err != nil {
		return &SOPINHandoffError{Stage: "parse platform.so-pin", Cause: err}
	}
	if !ref.IsKMS() {
		app.Logger.Warnf("sopin-handoff: platform.so-pin is not a kms:// reference; discarding the SO PIN staged at %s", path)
		return app.shredSOPINHandoff(path, len(data))
	}

	if store == nil {
		return &SOPINHandoffError{Stage: "store at " + ref.KMSPath, Cause: ErrSOPINHandoffSecretsUnavailable}
	}
	persisted, err := persistedSOPIN(ctx, store, ref.KMSPath)
	if err != nil {
		return err
	}
	defer clear(persisted)
	if persisted != nil {
		if bytes.Equal(persisted, data) {
			return app.shredSOPINHandoff(path, len(data))
		}
		if err := confirmStagedSOPIN(verify, ref.KMSPath, data); err != nil {
			var rejected *SOPINHandoffRejectedError
			if errors.As(err, &rejected) {
				app.Logger.Warn(rejected.Error())
				return app.shredSOPINHandoff(path, len(data))
			}
			return err
		}
	}

	if _, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name:        ref.KMSPath,
		Description: "TPM owner hierarchy auth (SO PIN) set by firstboot",
		Data:        data,
		Metadata: map[string]string{
			"source":       "firstboot-handoff",
			"content_type": "text/plain",
		},
	}); err != nil {
		return &SOPINHandoffError{Stage: "store at " + ref.KMSPath, Cause: err}
	}
	app.Logger.Info("sopin-handoff: SO PIN set by firstboot stored", "kms_path", ref.KMSPath)
	return app.shredSOPINHandoff(path, len(data))
}

// persistedSOPIN returns the SO PIN already stored at kmsPath, or nil when
// none is: the node's first provision.
func persistedSOPIN(ctx context.Context, store secretStore, kmsPath string) ([]byte, error) {
	rsp, err := store.GetSecret(ctx, &baasservice.GetSecretRequest{SecretID: kmsPath})
	if err != nil {
		if isSecureBootSecretNotFound(err) {
			return nil, nil
		}
		return nil, &SOPINHandoffError{Stage: "read " + kmsPath, Cause: err}
	}
	if rsp == nil {
		return nil, nil
	}
	return rsp.Data, nil
}

// confirmStagedSOPIN asks the TPM whether the staged SO PIN is its owner
// auth. A PIN the TPM rejects, or a TPM with no owner auth set, yields a
// SOPINHandoffRejectedError; any other failure is a SOPINHandoffError, so
// the staged file is kept for the next start to retry.
func confirmStagedSOPIN(verify ownerAuthVerifier, kmsPath string, staged []byte) error {
	pin, err := xkmssdk.NewPassword(staged)
	if err != nil {
		return &SOPINHandoffError{Stage: "read the staged SO PIN", Cause: err}
	}
	err = verify(pin)
	var rejected *tpmowner.OwnerAuthRejectedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &rejected), errors.Is(err, ErrSOPINHandoffTPMUnowned):
		return &SOPINHandoffRejectedError{KMSPath: kmsPath, Reason: err}
	default:
		return &SOPINHandoffError{Stage: "verify the staged SO PIN against the TPM owner hierarchy", Cause: err}
	}
}

// verifyOwnerAuthAtHandoff proves soPIN is the TPM owner hierarchy's auth.
// The handoff runs before InitTPM, so it opens the TPM itself when no TPM
// is open yet; InitTPM's OpenTPM then reuses app.TPM.
func (app *App) verifyOwnerAuthAtHandoff(soPIN xkmssdk.Password) error {
	if app.TPM == nil {
		if err := app.OpenTPM(false); err != nil && !errors.Is(err, xkmssdk.ErrTPMNotInitialized) {
			return err
		}
	}
	if app.TPM == nil {
		return ErrSOPINHandoffNoTPM
	}
	state, err := tpmowner.ReadHierarchyAuthState(app.TPM.Transport())
	if err != nil {
		return err
	}
	if !state.OwnerAuthSet {
		return ErrSOPINHandoffTPMUnowned
	}
	return tpmowner.VerifyOwnerAuth(app.TPM.Transport(), soPIN)
}

// shredSOPINHandoff shreds and unlinks the staged SO PIN.
func (app *App) shredSOPINHandoff(path string, size int) error {
	if err := shredAndUnlink(path, size); err != nil {
		return &SOPINHandoffError{Stage: "shred " + path, Cause: err}
	}
	return nil
}
