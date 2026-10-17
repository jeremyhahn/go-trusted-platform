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

package tpmclear

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// fakeTPM answers only Clear and Config. The embedded nil interface
// means any other call panics, so a change that starts calling
// something else is loud.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	cfg      *xkmssdk.TPMConfig
	clearErr error

	gotLockoutAuth []byte
	clearCalls     int
}

func (f *fakeTPM) Config() *xkmssdk.TPMConfig { return f.cfg }

func (f *fakeTPM) Clear(lockoutAuth []byte) error {
	f.clearCalls++
	f.gotLockoutAuth = lockoutAuth
	return f.clearErr
}

func ownedConfig() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{
		SSRK:        &xkmssdk.SRKConfig{HierarchyAuth: "so-pin"},
		EK:          &xkmssdk.EKConfig{HierarchyAuth: "so-pin"},
		PlatformSRK: &xkmssdk.PlatformSRKConfig{SRKAuth: "platform-srk-auth"},
	}
}

func TestClear_SuccessEmptiesOwnerAndEndorsementAuth(t *testing.T) {
	tpm := &fakeTPM{cfg: ownedConfig()}

	require.NoError(t, Clear(tpm, []byte("lockout")))

	assert.Equal(t, 1, tpm.clearCalls)
	assert.Equal(t, []byte("lockout"), tpm.gotLockoutAuth)
	assert.Empty(t, tpm.cfg.SSRK.HierarchyAuth, "owner hierarchy auth must match the cleared TPM")
	assert.Empty(t, tpm.cfg.EK.HierarchyAuth, "endorsement hierarchy auth must match the cleared TPM")
	assert.Equal(t, "platform-srk-auth", tpm.cfg.PlatformSRK.SRKAuth,
		"TPM2_Clear leaves the platform hierarchy alone")
}

func TestClear_RefusedClearKeepsAuth(t *testing.T) {
	refused := errors.New("TPM_RC_LOCKOUT")
	tpm := &fakeTPM{cfg: ownedConfig(), clearErr: refused}

	err := Clear(tpm, []byte("wrong"))

	require.ErrorIs(t, err, refused)
	assert.Equal(t, "so-pin", tpm.cfg.SSRK.HierarchyAuth)
	assert.Equal(t, "so-pin", tpm.cfg.EK.HierarchyAuth)
}

func TestClear_NilTPM(t *testing.T) {
	err := Clear(nil, nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
	assert.Equal(t, "TPM service not available", err.Error())
}

func TestClear_ToleratesMissingConfigSections(t *testing.T) {
	cases := map[string]*xkmssdk.TPMConfig{
		"no config":  nil,
		"no ssrk":    {EK: &xkmssdk.EKConfig{HierarchyAuth: "so-pin"}},
		"no ek":      {SSRK: &xkmssdk.SRKConfig{HierarchyAuth: "so-pin"}},
		"no section": {},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := &fakeTPM{cfg: cfg}

			require.NoError(t, Clear(tpm, nil))

			assert.Equal(t, 1, tpm.clearCalls)
			if cfg != nil && cfg.SSRK != nil {
				assert.Empty(t, cfg.SSRK.HierarchyAuth)
			}
			if cfg != nil && cfg.EK != nil {
				assert.Empty(t, cfg.EK.HierarchyAuth)
			}
		})
	}
}
