package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

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

// ConsumeSOPINHandoff stores the SO PIN firstboot staged at the KMS path
// platform.so-pin names. It must run after initStores and before
// ProcessSecrets. No staged file is a no-op.
func (app *App) ConsumeSOPINHandoff(ctx context.Context) error {
	return app.consumeSOPINHandoff(ctx, app.secureBootSecretStore(), tpmowner.SOPINHandoffFile)
}

// consumeSOPINHandoff is ConsumeSOPINHandoff against an explicit secret
// store and handoff path. The staged file is shredded once the PIN is stored,
// or when platform.so-pin no longer names a KMS path to store it at.
func (app *App) consumeSOPINHandoff(ctx context.Context, store secretStore, path string) error {
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

// shredSOPINHandoff shreds and unlinks the staged SO PIN.
func (app *App) shredSOPINHandoff(path string, size int) error {
	if err := shredAndUnlink(path, size); err != nil {
		return &SOPINHandoffError{Stage: "shred " + path, Cause: err}
	}
	return nil
}
