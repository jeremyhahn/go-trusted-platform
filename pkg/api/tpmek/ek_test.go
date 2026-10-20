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

package tpmek

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

const testEKHandle = tpm2.TPMHandle(0x81010001)

// fakeTPM answers only EKAttributes, ReadHandle and CreateEK. The
// embedded nil interface means any other call panics, so a change that
// starts calling something else is loud.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule

	ekAttrs    *xkmssdk.KeyAttributes
	ekAttrsErr error
	readErr    error
	createErr  error

	readHandle  tpm2.TPMHandle
	createCalls int
}

func (f *fakeTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return f.ekAttrs, f.ekAttrsErr
}

func (f *fakeTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	f.readHandle = handle
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, f.readErr
}

func (f *fakeTPM) CreateEK(*xkmssdk.KeyAttributes) error {
	f.createCalls++
	return f.createErr
}

// absentHandle is what ReadHandle returns for an empty persistent handle.
var absentHandle = errors.New("TPM_RC_HANDLE")

func configuredEK() *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{
			Handle:   testEKHandle,
			Template: tpm2.RSAEKTemplate,
		},
	}
}

func TestCreate_CreatesFromConfiguredTemplate(t *testing.T) {
	tpm := &fakeTPM{ekAttrs: configuredEK(), readErr: absentHandle}

	got, err := Create(tpm)

	require.NoError(t, err)
	assert.Same(t, tpm.ekAttrs, got)
	assert.Equal(t, testEKHandle, tpm.readHandle, "Create must probe the configured EK handle")
	assert.Equal(t, 1, tpm.createCalls)
}

func TestCreate_OccupiedHandleIsAlreadyExists(t *testing.T) {
	tpm := &fakeTPM{ekAttrs: configuredEK()}

	_, err := Create(tpm)

	require.ErrorAs(t, err, &ErrEKExists{})
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Contains(t, err.Error(), "0x81010001")
	assert.Zero(t, tpm.createCalls, "an occupied handle must never reach CreatePrimary")
}

// The persistent EK read back by EKAttributes carries no template; once
// the handle is empty again (TPM2_Clear) the zero TPMT_PUBLIC used to
// panic go-tpm's marshaller.
func TestCreate_TemplateLessAttributesAreFailedPrecondition(t *testing.T) {
	attrs := configuredEK()
	attrs.TPMAttributes.Template = tpm2.TPMTPublic{}
	tpm := &fakeTPM{ekAttrs: attrs, readErr: absentHandle}

	_, err := Create(tpm)

	require.ErrorAs(t, err, &ErrEKTemplateUnavailable{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Zero(t, tpm.createCalls)
}

func TestCreate_MissingTPMAttributesAreFailedPrecondition(t *testing.T) {
	tpm := &fakeTPM{ekAttrs: &xkmssdk.KeyAttributes{}}

	_, err := Create(tpm)

	require.ErrorAs(t, err, &ErrEKTemplateUnavailable{})
	assert.Zero(t, tpm.createCalls)
}

func TestCreate_PropagatesBackendErrors(t *testing.T) {
	attrsErr := errors.New("EK config is nil")
	createErr := errors.New("TPM_RC_BAD_AUTH")
	cases := map[string]struct {
		tpm  *fakeTPM
		want error
	}{
		"EKAttributes": {tpm: &fakeTPM{ekAttrsErr: attrsErr}, want: attrsErr},
		"CreateEK": {
			tpm:  &fakeTPM{ekAttrs: configuredEK(), readErr: absentHandle, createErr: createErr},
			want: createErr,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Create(tc.tpm)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestCreate_NilTPM(t *testing.T) {
	_, err := Create(nil)

	require.ErrorAs(t, err, &ErrTPMUnavailable{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
