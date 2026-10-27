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

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// enrollmentRefused is a typed refusal from the enrollment server.
type enrollmentRefused struct{ reason string }

func (e enrollmentRefused) Error() string { return "enrollment refused: " + e.reason }

// enrollingApp is an App configured for ACME device enrollment, with a TPM
// certificate store and a CA that record what they are given.
func enrollingApp(t *testing.T, challenge string) (*App, *bootingDisklessTPM, *importingCA) {
	t.Helper()
	platform := &App{}
	yaml := "acme:\n  client:\n    enrollment:\n      challenge: " + challenge + "\n"
	require.NoError(t, config.DecodeYAML([]byte(yaml), platform))
	tpm := newBootingDisklessTPM(t)
	ca := &importingCA{}
	platform.Hostname = "node-1.example"
	platform.Logger = logging.DefaultLogger()
	platform.TPM = tpm
	platform.CA = ca
	return platform, tpm, ca
}

// enrolledCerts is an issuing CA and the IAK and IDevID it issued.
func enrolledCerts(t *testing.T) *enrolledIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer := issueTestCert(t, 1, "cp-intermediate", true, key.Public(), nil, key)
	return &enrolledIdentity{
		chain:  []*x509.Certificate{issuer},
		iak:    issueTestCert(t, 2, "node-1-iak", false, key.Public(), issuer, key),
		idevid: issueTestCert(t, 3, "node-1-idevid", false, key.Public(), issuer, key),
	}
}

func TestEnrollIdentity_StoresWhatEnrollmentIssued(t *testing.T) {
	platform, tpm, ca := enrollingApp(t, "enroll-01")
	issued := enrolledCerts(t)
	var asked *trustedca.ACMEEnrollmentConfig
	platform.enrollDevice = func(_ context.Context, cfg *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
		asked = cfg
		return issued, nil
	}

	idevid, err := platform.EnrollIdentity(context.Background())

	require.NoError(t, err)
	assert.Same(t, issued.idevid, idevid)
	require.NotNil(t, asked)
	assert.Equal(t, "enroll-01", asked.Challenge)
	assert.Equal(t, "node-1.example", asked.CommonName)
	assert.NotNil(t, asked.TPMModule)
	assert.Same(t, issued.iak, tpm.storedIAK)
	assert.Same(t, issued.idevid, tpm.storedIDevID)
	assert.Equal(t, []*x509.Certificate{issued.chain[0], issued.iak, issued.idevid}, ca.imported,
		"the issuing chain is imported before the leaves")
}

func TestEnrollIdentity_EnrollmentFailureKeepsItsTypedError(t *testing.T) {
	platform, tpm, ca := enrollingApp(t, "endorse-01")
	platform.enrollDevice = func(context.Context, *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
		return nil, enrollmentRefused{reason: "EAB rejected"}
	}

	idevid, err := platform.EnrollIdentity(context.Background())

	assert.Nil(t, idevid)
	var refused enrollmentRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	assert.Equal(t, "EAB rejected", refused.reason)
	assert.Nil(t, tpm.storedIAK)
	assert.Nil(t, tpm.storedIDevID)
	assert.Empty(t, ca.imported)
}

func TestEnrollIdentity_TPMStoreFailure(t *testing.T) {
	platform, tpm, _ := enrollingApp(t, "enroll-01")
	tpm.storeErr = errors.New("NV write refused")
	issued := enrolledCerts(t)
	platform.enrollDevice = func(context.Context, *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
		return issued, nil
	}

	idevid, err := platform.EnrollIdentity(context.Background())

	assert.Nil(t, idevid)
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "got %v", err)
	assert.ErrorIs(t, err, tpm.storeErr)
}

// A server that issued no IDevID leaves the caller to refuse: the
// installer's enrollNBDIdentity does.
func TestEnrollIdentity_NoIDevIDIssued(t *testing.T) {
	platform, tpm, _ := enrollingApp(t, "enroll-01")
	issued := enrolledCerts(t)
	issued.idevid = nil
	platform.enrollDevice = func(context.Context, *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
		return issued, nil
	}

	idevid, err := platform.EnrollIdentity(context.Background())

	require.NoError(t, err)
	assert.Nil(t, idevid)
	assert.Same(t, issued.iak, tpm.storedIAK)
}

func TestEnrollIdentity_Unavailable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*App)
		missing string
	}{
		{"no acme section", func(a *App) { a.ACMEConfig = nil }, "the acme.client.enrollment configuration"},
		{"no enrollment", func(a *App) { a.ACMEConfig.Client.Enrollment = nil }, "the acme.client.enrollment configuration"},
		{"no TPM", func(a *App) { a.TPM = nil }, "an open TPM"},
		{"no CA", func(a *App) { a.CA = nil }, "the platform CA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform, _, _ := enrollingApp(t, "enroll-01")
			tt.mutate(platform)

			idevid, err := platform.EnrollIdentity(context.Background())

			assert.Nil(t, idevid)
			var unavailable ErrEnrollmentUnavailable
			require.True(t, errors.As(err, &unavailable), "got %v", err)
			assert.Equal(t, tt.missing, unavailable.Missing)
			assert.Nil(t, platform.ACMEClient)
		})
	}
}

// With no test seam, EnrollIdentity enrols through the SDK ACME client, whose
// own refusal comes back unchanged and leaves nothing stored.
func TestEnrollIdentity_ThroughTheSDKClient(t *testing.T) {
	platform, tpm, ca := enrollingApp(t, "bogus-01")
	platform.ACMEClient = &trustedca.ACMEClient{}

	idevid, err := platform.EnrollIdentity(context.Background())

	assert.Nil(t, idevid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid enrollment config")
	assert.Nil(t, tpm.storedIDevID)
	assert.Empty(t, ca.imported)
}

func TestErrEnrollmentUnavailable_Error(t *testing.T) {
	err := ErrEnrollmentUnavailable{Missing: "an open TPM"}
	assert.Equal(t, "app: device enrollment is unavailable: an open TPM is missing", err.Error())
	assert.NotEqual(t, err.Error(), ErrEnrollmentUnavailable{Missing: "the platform CA"}.Error())
}
