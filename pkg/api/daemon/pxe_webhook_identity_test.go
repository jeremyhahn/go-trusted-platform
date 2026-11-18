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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	webv1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
)

const (
	webhookIdentityMAC    = "aa:bb:cc:dd:ee:01"
	webhookIdentitySecret = "s3cret"
)

// webhookIdentityFixture is a real PXE service (initialized, not started)
// behind the daemon's gRPC adapter and the REST router, with no
// SetWebhookIdentity: the webhook reads the IDevID fingerprint recorded at
// enrolment through the service, as platformd does (ruling 673).
type webhookIdentityFixture struct {
	svc      pxe.Service
	root     *mux.Router
	deviceID string
}

func newWebhookIdentityFixture(t *testing.T) *webhookIdentityFixture {
	t.Helper()
	ctx := context.Background()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)
	cfg, err := pxe.NewServiceConfig(plan)
	require.NoError(t, err)
	cfg.BridgeName = "br-test"
	// Initialize builds (but does not start) the iPXE server, which needs a
	// boot entry; the service is never started, so nothing is served.
	cfg.IPXEConfig.LocalFilesDir = t.TempDir()
	cfg.IPXEConfig.InstallsDir = t.TempDir()
	cfg.IPXEConfig.FirmwareDir = t.TempDir()
	cfg.IPXEConfig.FirmwareOffline = true
	// Pin the server address: a CI container without a routable interface
	// cannot auto-detect one (#1896).
	cfg.IPXEConfig.BindHost = "127.0.0.1"
	cfg.IPXEConfig.BootEntries = []ipxe.BootEntry{
		{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
	}

	svc := pxe.NewService(
		pxe.WithStateManager(pxe.NewStateManager()),
		pxe.WithVLANIntegration(pxe.NewNoopVLANIntegration(plan)),
	)
	require.NoError(t, svc.Initialize(ctx, cfg))

	device, err := svc.RegisterDevice(ctx, webhookIdentityMAC, "port-1")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, pxe.StateBooting, "booting"))
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, pxe.StateInstalling, "installing"))

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	grpcSvc := NewPXEGRPCService(logger, svc)
	router := restpxe.NewPXERouter(logger, grpcSvc, response.NewResponseWriter(logger, nil), true)
	router.SetWebhookSecret(webhookIdentitySecret)
	root := mux.NewRouter()
	router.RegisterMachineFacingRoutes(root.PathPrefix("/api/v1").Subrouter())
	return &webhookIdentityFixture{svc: svc, root: root, deviceID: device.ID}
}

// report posts a signed, successful install-completion report for the
// fixture's device, over a connection whose verified client leaf is cert.
func (f *webhookIdentityFixture) report(cert *x509.Certificate) *httptest.ResponseRecorder {
	body := `{"macAddress":"` + webhookIdentityMAC + `","hostname":"node-1","success":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", strings.NewReader(body))
	req.Header.Set(restpxe.WebhookSignatureHeader, restpxe.SignWebhookBody([]byte(webhookIdentitySecret), []byte(body)))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	rec := httptest.NewRecorder()
	f.root.ServeHTTP(rec, req)
	return rec
}

func (f *webhookIdentityFixture) state(t *testing.T) pxe.ProvisioningState {
	t.Helper()
	d, err := f.svc.GetDevice(context.Background(), f.deviceID)
	require.NoError(t, err)
	return d.State
}

// webhookIdentityCert is a self-signed client certificate standing in for
// a device's IDevID.
func webhookIdentityCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func webhookIdentityFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TestPXEWebhook_InstallingDeviceWithRecordedIDevIDCompletes is Codex round
// 5's P1 (a) on #1896: a fresh device reporting from installing, whose IDevID
// fingerprint was recorded at enrolment, completes through the real service;
// the cert-serial binding refused it 403 because only SetDeviceEnrolled,
// after install completion, recorded a serial (ruling 673).
func TestPXEWebhook_InstallingDeviceWithRecordedIDevIDCompletes(t *testing.T) {
	ctx := context.Background()
	cert := webhookIdentityCert(t)

	f := newWebhookIdentityFixture(t)
	require.NoError(t, f.svc.RecordIDevIDFingerprint(ctx, f.deviceID, webhookIdentityFingerprint(cert)))

	rec := f.report(cert)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstallComplete, f.state(t))

	t.Run("no IDevID recorded", func(t *testing.T) {
		f := newWebhookIdentityFixture(t)
		rec := f.report(cert)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, pxe.StateInstalling, f.state(t))
	})

	t.Run("another certificate", func(t *testing.T) {
		f := newWebhookIdentityFixture(t)
		require.NoError(t, f.svc.RecordIDevIDFingerprint(ctx, f.deviceID, webhookIdentityFingerprint(cert)))
		rec := f.report(webhookIdentityCert(t))
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, pxe.StateInstalling, f.state(t))
	})
}

// stubMACForIP answers mac for ip and "" for any other address, the way an
// ARP table answers for an address that is not on-link.
func stubMACForIP(t *testing.T, ip, mac string) {
	t.Helper()
	orig := macForIP
	macForIP = func(addr string) string {
		if addr == ip {
			return mac
		}
		return ""
	}
	t.Cleanup(func() { macForIP = orig })
}

// TestPXEIdentityHook_EnrolmentRecordsTheIDevIDTheWebhookRequires drives the
// production path (#1694, Codex P1 on #1896): the ACME finalize hook records
// the issued IDevID's fingerprint on the PXE record of the enrolling MAC, and
// the install-complete webhook then accepts that IDevID over mTLS.
func TestPXEIdentityHook_EnrolmentRecordsTheIDevIDTheWebhookRequires(t *testing.T) {
	const clientIP = "192.0.2.10"
	ctx := context.Background()
	cert := webhookIdentityCert(t)
	f := newWebhookIdentityFixture(t)
	stubMACForIP(t, clientIP, webhookIdentityMAC)

	// Before enrolment nothing is recorded, so the webhook refuses.
	rec := f.report(cert)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	hook := webv1.NewPXEIdentityHook(NewPXEGRPCService(logger, f.svc), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     ctx,
		IsTCGCSR:    true,
		ClientIP:    clientIP,
		Certificate: cert,
	}))

	rec = f.report(cert)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstallComplete, f.state(t))
}

// TestPXEIdentityHook_NoPXEBackendDoesNotFailEnrolment covers the production
// configuration: platformd builds the PXE gRPC service with no backend, and
// a TCG enrolment on such a node must still succeed.
func TestPXEIdentityHook_NoPXEBackendDoesNotFailEnrolment(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	hook := webv1.NewPXEIdentityHook(NewPXEGRPCService(logger, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		ClientIP:    "192.0.2.10",
		Certificate: webhookIdentityCert(t),
	}))
}

// TestPXEIdentityHook_UnresolvableIPRecordsNothing pins that an enrolment
// from an address with no on-link MAC (not a PXE install) still succeeds and
// records no fingerprint, so the webhook keeps refusing.
func TestPXEIdentityHook_UnresolvableIPRecordsNothing(t *testing.T) {
	ctx := context.Background()
	cert := webhookIdentityCert(t)
	f := newWebhookIdentityFixture(t)
	stubMACForIP(t, "192.0.2.10", webhookIdentityMAC)

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	grpcSvc := NewPXEGRPCService(logger, f.svc)
	hook := webv1.NewPXEIdentityHook(grpcSvc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     ctx,
		IsTCGCSR:    true,
		ClientIP:    "198.51.100.7",
		Certificate: cert,
	}))

	fp, err := grpcSvc.RecordedIDevIDFingerprint(ctx, webhookIdentityMAC)
	require.NoError(t, err)
	assert.Empty(t, fp)

	err = grpcSvc.RecordEnrolledIDevIDFingerprint(ctx, "198.51.100.7", cert)
	assert.Equal(t, codes.NotFound, status.Code(err), "an unresolvable IP is a typed not-found")

	rec := f.report(cert)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstalling, f.state(t))
}

// webhookEKProfiles resolves a device profile by its exact EK serial.
type webhookEKProfiles map[string]*deviceentities.DeviceProfile

func (p webhookEKProfiles) FindConfigForDevice(_ context.Context, ekSerial, mac string) (*deviceentities.DeviceProfile, error) {
	if profile, ok := p[ekSerial]; ok {
		return profile, nil
	}
	return nil, devicepkg.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
}

// A device that enrols across a router has no neighbour entry on the control
// plane; its EK-bound profile names the PXE device, so the webhook accepts
// the IDevID it was issued.
func TestPXEIdentityHook_RoutedEnrolmentCompletesThroughTheWebhook(t *testing.T) {
	ctx := context.Background()
	cert := webhookIdentityCert(t)
	ek := webhookIdentityCert(t)
	f := newWebhookIdentityFixture(t)
	stubMACForIP(t, "192.0.2.10", webhookIdentityMAC)
	profiles := webhookEKProfiles{ek.SerialNumber.String(): {MACAddress: webhookIdentityMAC}}

	logger := logging.NewLogger(slog.LevelError, io.Discard)
	hook := webv1.NewPXEIdentityHookWithProfiles(NewPXEGRPCService(logger, f.svc), profiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     ctx,
		IsTCGCSR:    true,
		ClientIP:    "198.51.100.7",
		Certificate: cert,
		TCGData:     &trustedca.ACMETCGEnrollmentData{EKCertificate: ek},
	}))

	rec := f.report(cert)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, pxe.StateInstallComplete, f.state(t))
}
