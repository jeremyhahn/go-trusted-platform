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

package daemon

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	webv1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// fingerprintBindingHook wires the PXE identity hook to f's service with one
// EK-bound profile naming the fixture's MAC, and returns a finalize function
// that runs the hook for an issued IDevID, plus the gRPC service the hook
// records through.
func fingerprintBindingHook(t *testing.T, f *webhookIdentityFixture) (func(*x509.Certificate) error, *PXEGRPCService) {
	t.Helper()
	ek := webhookIdentityCert(t)
	profiles := webhookEKProfiles{ek.SerialNumber.String(): {MACAddress: webhookIdentityMAC, EKCert: webhookEKPEM(ek)}}
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	grpcSvc := NewPXEGRPCService(logger, f.svc)
	hook := webv1.NewPXEIdentityHookWithProfiles(grpcSvc, profiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	finalize := func(cert *x509.Certificate) error {
		return hook(&trustedca.ACMEOrderFinalizeHookContext{
			Context:     context.Background(),
			IsTCGCSR:    true,
			ClientIP:    "192.0.2.10",
			Certificate: cert,
			TCGData:     &trustedca.ACMETCGEnrollmentData{EKCertificate: ek},
		})
	}
	return finalize, grpcSvc
}

// Owner ruling 1234, first half: the fingerprint recorded at enrolment is
// advisory and replaceable until the install-complete webhook presents it. A
// re-enrolment while installing replaces it, so the earlier IDevID is refused
// and the later one completes the install.
func TestPXEIdentityHook_ReEnrolmentBeforeCompletionReplacesTheFingerprint(t *testing.T) {
	ctx := context.Background()
	f := newWebhookIdentityFixture(t)
	finalize, grpcSvc := fingerprintBindingHook(t, f)

	certA := webhookIdentityCert(t)
	certB := webhookIdentityCert(t)
	require.NoError(t, finalize(certA))
	require.NoError(t, finalize(certB))

	fp, err := grpcSvc.RecordedIDevIDFingerprint(ctx, webhookIdentityMAC)
	require.NoError(t, err)
	require.Equal(t, webhookIdentityFingerprint(certB), fp)

	rec := f.report(certA)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstalling, f.state(t))

	rec = f.report(certB)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstallComplete, f.state(t))
}

// Owner ruling 1234, second half: once the install-complete webhook has
// presented the fingerprint it is binding. A later enrolment is not failed,
// but it does not change the recorded fingerprint, and its IDevID is refused
// by the webhook.
func TestPXEIdentityHook_EnrolmentAfterCompletionKeepsTheBindingFingerprint(t *testing.T) {
	ctx := context.Background()
	f := newWebhookIdentityFixture(t)
	finalize, grpcSvc := fingerprintBindingHook(t, f)

	certA := webhookIdentityCert(t)
	require.NoError(t, finalize(certA))
	rec := f.report(certA)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, pxe.StateInstallComplete, f.state(t))

	certB := webhookIdentityCert(t)
	require.NoError(t, finalize(certB), "an enrolment after install completion is not failed")

	fp, err := grpcSvc.RecordedIDevIDFingerprint(ctx, webhookIdentityMAC)
	require.NoError(t, err)
	assert.Equal(t, webhookIdentityFingerprint(certA), fp, "the webhook-presented fingerprint is binding")

	rec = f.report(certB)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}
