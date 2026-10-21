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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmsrk"
)

// SSRKProbeError is returned when the Shared SRK handle cannot be read for a
// reason other than the handle being empty.
type SSRKProbeError struct {
	Handle uint32
	Cause  error
}

// Error returns the error message.
func (e *SSRKProbeError) Error() string {
	return fmt.Sprintf("app: failed to read the Shared SRK handle 0x%08X: %v", e.Handle, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *SSRKProbeError) Unwrap() error { return e.Cause }

// SSRKCreateError is returned when the Shared SRK cannot be created and
// persisted at its configured handle.
type SSRKCreateError struct {
	Handle uint32
	Cause  error
}

// Error returns the error message.
func (e *SSRKCreateError) Error() string {
	return fmt.Sprintf("app: failed to create the Shared SRK at 0x%08X: %v", e.Handle, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *SSRKCreateError) Unwrap() error { return e.Cause }

// ensureSSRK creates the Shared SRK (tpm.ssrk) at its configured persistent
// handle when the TPM holds nothing there. Operator seal/unseal, SRK info and
// vTPM bundle sealing all parent on it (docs/tpm/engineering.md §4).
//
// The full Provision creates it, but a TPM that already holds its EK (the
// swtpm_setup state, or a node without an IAK/IDevID configured) never runs
// Provision, so without this step the handle stays empty and every SSRK
// consumer fails with TPM_RC_HANDLE. The key is a primary under the owner
// hierarchy, created with the owner auth the TPM reports
// (applyTPMHierarchyAuth): empty before ownership is taken, the SO PIN after.
// An SSRK already at the handle is left untouched.
func (app *App) ensureSSRK() error {
	cfg := app.TPMConfig.SSRK
	if cfg == nil || cfg.Handle == 0 {
		return nil
	}
	_, _, err := app.TPM.ReadHandle(libtpm2.TPMHandle(cfg.Handle))
	if err == nil {
		return nil
	}
	if !errors.Is(err, libtpm2.TPMRCHandle) && !errors.Is(err, libtpm2.TPMRCValue) {
		return &SSRKProbeError{Handle: cfg.Handle, Cause: err}
	}
	if _, err := tpmsrk.Persist(app.TPM, cfg, app.TPMConfig.EncryptSession); err != nil {
		return &SSRKCreateError{Handle: cfg.Handle, Cause: err}
	}
	app.Logger.Info("Shared SRK created", "handle", fmt.Sprintf("0x%08X", cfg.Handle))
	return nil
}
