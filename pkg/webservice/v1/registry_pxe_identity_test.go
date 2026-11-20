package v1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/require"
)

// unconfiguredPXERecorder is a PXE service with no backend: it reports
// itself unconfigured and fails the test if the hook records anything.
type unconfiguredPXERecorder struct{ t *testing.T }

func (r unconfiguredPXERecorder) Configured() bool { return false }

func (r unconfiguredPXERecorder) RecordEnrolledIDevIDFingerprintForMAC(context.Context, string, *x509.Certificate) error {
	r.t.Error("the PXE identity hook recorded a fingerprint with PXE disabled")
	return nil
}

// serialOnlyProfiles resolves a profile by EK serial with no bound EK
// certificate, as AssignToDeviceWithEK allows.
type serialOnlyProfiles map[string]*deviceentities.DeviceProfile

func (p serialOnlyProfiles) FindConfigForDevice(_ context.Context, ekSerial, mac string) (*deviceentities.DeviceProfile, error) {
	if profile, ok := p[ekSerial]; ok {
		return profile, nil
	}
	return nil, devicepkg.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
}

func pxeIdentityTestCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// Codex round 4 P1 on #1896: with PXE disabled the identity hook imposes
// no PXE profile requirement, so a serial-only profile still enrols.
func TestPXEIdentityHook_DisabledPXESkipsTheProfileCheck(t *testing.T) {
	ek := pxeIdentityTestCert(t, 2002)
	profiles := serialOnlyProfiles{ek.SerialNumber.String(): {MACAddress: "02:00:00:00:00:01"}}
	hook := NewPXEIdentityHookWithProfiles(unconfiguredPXERecorder{t: t}, profiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		ClientIP:    "192.0.2.10",
		Certificate: pxeIdentityTestCert(t, 2003),
		TCGData:     &trustedca.ACMETCGEnrollmentData{EKCertificate: ek},
	}))
}

// idleMACPXERecorder is an enabled PXE backend on which no MAC has a PXE
// install in progress. Recording is a test failure.
type idleMACPXERecorder struct {
	t       *testing.T
	queried []string
}

func (r *idleMACPXERecorder) Configured() bool { return true }

func (r *idleMACPXERecorder) PXEInstallInProgressForMAC(_ context.Context, mac string) (bool, error) {
	r.queried = append(r.queried, mac)
	return false, nil
}

func (r *idleMACPXERecorder) RecordEnrolledIDevIDFingerprintForMAC(context.Context, string, *x509.Certificate) error {
	r.t.Error("the PXE identity hook recorded a fingerprint for a device outside the PXE workflow")
	return nil
}

// Codex round 5 P1 on #1896: with PXE enabled, a serial-only profile (no EK
// certificate registered, as AssignToDevice allows) outside the PXE workflow
// still enrolls and renews. The EK binding applies only to an active PXE
// install.
func TestPXEIdentityHook_EnabledPXESerialOnlyProfileOutsidePXEEnrolls(t *testing.T) {
	cases := map[string]*deviceentities.DeviceProfile{
		"MAC with no PXE install": {MACAddress: "02:00:00:00:00:02"},
		"no MAC":                  {},
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			ek := pxeIdentityTestCert(t, 2004)
			profiles := serialOnlyProfiles{ek.SerialNumber.String(): profile}
			rec := &idleMACPXERecorder{t: t}
			hook := NewPXEIdentityHookWithProfiles(rec, profiles, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, hook(&trustedca.ACMEOrderFinalizeHookContext{
				Context:     context.Background(),
				IsTCGCSR:    true,
				ClientIP:    "192.0.2.11",
				Certificate: pxeIdentityTestCert(t, 2005),
				TCGData:     &trustedca.ACMETCGEnrollmentData{EKCertificate: ek},
			}))
		})
	}
}
