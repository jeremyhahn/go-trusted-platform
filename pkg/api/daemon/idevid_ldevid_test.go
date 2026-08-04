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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// LDevID test doubles
// =============================================================================

// ldevidMockPKS is a minimal PlatformKeyStorer for LDevID key creation.
type ldevidMockPKS struct {
	xkmssdk.PlatformKeyStorer
}

func (m *ldevidMockPKS) SRKAttributes() *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{}
}

func (m *ldevidMockPKS) Backend() xkmssdk.TPMKeyBackend {
	return nil
}

// ldevidMockTPM implements the subset of TrustedPlatformModule used by
// CreateLDevID. All other methods panic (via the embedded nil interface) to
// keep the test honest about which TPM operations the handler touches.
type ldevidMockTPM struct {
	xkmssdk.TrustedPlatformModule

	idevidCert     *x509.Certificate
	idevidCertErr  error
	pks            xkmssdk.PlatformKeyStorer
	pksNil         bool
	ecKey          *ecdsa.PrivateKey
	createECDSAErr error
}

func (m *ldevidMockTPM) IDevIDCertificate() (*x509.Certificate, error) {
	return m.idevidCert, m.idevidCertErr
}

func (m *ldevidMockTPM) PlatformKeyStore() xkmssdk.PlatformKeyStorer {
	if m.pksNil {
		return nil
	}
	return m.pks
}

func (m *ldevidMockTPM) CreateECDSA(_ *xkmssdk.KeyAttributes, _ xkmssdk.TPMKeyBackend, _ bool) (*ecdsa.PublicKey, error) {
	if m.createECDSAErr != nil {
		return nil, m.createECDSAErr
	}
	return &m.ecKey.PublicKey, nil
}

func (m *ldevidMockTPM) CreateRSA(_ *xkmssdk.KeyAttributes, _ xkmssdk.TPMKeyBackend, _ bool) (*rsa.PublicKey, error) {
	return nil, errors.New("rsa key creation not wired in test")
}

// Sign produces a real ECDSA signature over the digest with the LDevID key so
// x509.CreateCertificateRequest can verify the returned CSR signature. On real
// hardware this delegates to the TPM; here we sign in software.
func (m *ldevidMockTPM) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, m.ecKey, digest)
}

// ldevidMockCA implements the CA seam used to issue the LDevID certificate.
type ldevidMockCA struct {
	quicbaasca.CACertificateAuthority

	cert        *x509.Certificate
	err         error
	gotProfile  string
	gotValidity int
	gotCSR      []byte
}

func (m *ldevidMockCA) SignCSR(_ context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	m.gotCSR = csrPEM
	if opts != nil {
		m.gotProfile = opts.Profile
		m.gotValidity = opts.ValidityDays
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.cert, nil
}

// ldevidTestCert builds a self-signed ECDSA certificate over the given window.
func ldevidTestCert(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func newLDevIDTestService(t *testing.T) *IDevIDGRPCService {
	t.Helper()
	return NewIDevIDGRPCService(logging.DefaultLogger())
}

func ldevidHappyTPM(t *testing.T) *ldevidMockTPM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ldevid key: %v", err)
	}
	now := time.Now()
	return &ldevidMockTPM{
		idevidCert: ldevidTestCert(t, "device-01", now.Add(-time.Hour), now.Add(24*time.Hour)),
		pks:        &ldevidMockPKS{},
		ecKey:      key,
	}
}

// =============================================================================
// Happy path
// =============================================================================

func TestCreateLDevID_Success(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))

	now := time.Now()
	ca := &ldevidMockCA{cert: ldevidTestCert(t, "device-01-ldevid", now, now.Add(90*24*time.Hour))}
	svc.SetCAService(ca)

	resp, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{
		Template: &platformv1.CSRTemplate{
			CommonName:   "device-01-ldevid",
			Organization: "Automate The Things",
			DnsNames:     []string{"device-01.local"},
		},
		Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		Profile:      "ldevid",
		ValidityDays: 90,
	})
	if err != nil {
		t.Fatalf("CreateLDevID() error = %v", err)
	}
	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Fatalf("expected success status, got %+v", resp.GetStatus())
	}
	if len(resp.GetCsrPem()) == 0 {
		t.Error("expected non-empty CSR PEM")
	}
	if len(resp.GetCertificatePem()) == 0 {
		t.Error("expected non-empty certificate PEM")
	}
	if resp.GetCertificate() == nil || resp.GetCertificate().GetKeyType() != "LDevID" {
		t.Errorf("expected certificate KeyType LDevID, got %+v", resp.GetCertificate())
	}
	if resp.GetCertificate().GetTpmHandle() != defaultLDevIDHandle {
		t.Errorf("expected default LDevID handle 0x%08x, got 0x%08x", defaultLDevIDHandle, resp.GetCertificate().GetTpmHandle())
	}
	if ca.gotProfile != "ldevid" || ca.gotValidity != 90 {
		t.Errorf("CA sign options not propagated: profile=%q validity=%d", ca.gotProfile, ca.gotValidity)
	}
	if len(ca.gotCSR) == 0 {
		t.Error("CA did not receive a CSR")
	}
}

func TestCreateLDevID_DefaultsCNFromIDevID(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))
	now := time.Now()
	ca := &ldevidMockCA{cert: ldevidTestCert(t, "device-01", now, now.Add(24*time.Hour))}
	svc.SetCAService(ca)

	// No template CN provided: handler should fall back to the IDevID subject CN.
	resp, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if err != nil {
		t.Fatalf("CreateLDevID() error = %v", err)
	}
	if len(resp.GetCsrPem()) == 0 {
		t.Fatal("expected non-empty CSR PEM")
	}
}

// =============================================================================
// Error paths
// =============================================================================

func TestCreateLDevID_TPMNotConfigured(t *testing.T) {
	svc := newLDevIDTestService(t)
	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestCreateLDevID_CANotConfigured(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))
	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
	if got := status.Convert(err).Message(); got != (ErrLDevIDCANotConfigured{}).Error() {
		t.Errorf("unexpected message: %q", got)
	}
}

func TestCreateLDevID_NoIDevIDCertificate(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(&ldevidMockTPM{idevidCertErr: errors.New("not found"), pks: &ldevidMockPKS{}})
	svc.SetCAService(&ldevidMockCA{})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
	if got := status.Convert(err).Message(); !strings.Contains(got, "no proven IDevID") {
		t.Errorf("expected gate refusal message, got %q", got)
	}
}

func TestCreateLDevID_NilIDevIDCertificate(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(&ldevidMockTPM{idevidCert: nil, pks: &ldevidMockPKS{}})
	svc.SetCAService(&ldevidMockCA{})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestCreateLDevID_ExpiredIDevIDCertificate(t *testing.T) {
	svc := newLDevIDTestService(t)
	past := time.Now().Add(-48 * time.Hour)
	svc.SetTPM2Service(&ldevidMockTPM{
		idevidCert: ldevidTestCert(t, "device-01", past, past.Add(time.Hour)),
		pks:        &ldevidMockPKS{},
	})
	svc.SetCAService(&ldevidMockCA{})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
	if got := status.Convert(err).Message(); !strings.Contains(got, "validity window") {
		t.Errorf("expected validity-window refusal, got %q", got)
	}
}

func TestCreateLDevID_CASigningFails(t *testing.T) {
	svc := newLDevIDTestService(t)
	svc.SetTPM2Service(ldevidHappyTPM(t))
	svc.SetCAService(&ldevidMockCA{err: errors.New("ca offline")})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{
		Algorithm: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

func TestCreateLDevID_PlatformKeyStoreUnavailable(t *testing.T) {
	svc := newLDevIDTestService(t)
	tpm := ldevidHappyTPM(t)
	tpm.pksNil = true
	svc.SetTPM2Service(tpm)
	svc.SetCAService(&ldevidMockCA{})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

func TestCreateLDevID_KeyCreationFails(t *testing.T) {
	svc := newLDevIDTestService(t)
	tpm := ldevidHappyTPM(t)
	tpm.createECDSAErr = errors.New("tpm object memory")
	svc.SetTPM2Service(tpm)
	svc.SetCAService(&ldevidMockCA{})

	_, err := svc.CreateLDevID(context.Background(), &platformv1.CreateLDevIDRequest{
		Algorithm: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	})
	if status.Code(err) == codes.OK {
		t.Fatalf("expected error, got nil")
	}
}

func TestLDevIDAlgorithmParams(t *testing.T) {
	cases := []struct {
		algo    platformv1.DeviceKeyAlgorithm
		keyAlgo x509.PublicKeyAlgorithm
		ecc     bool
	}{
		{platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED, x509.ECDSA, true},
		{platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256, x509.ECDSA, true},
		{platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384, x509.ECDSA, true},
		{platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048, x509.RSA, false},
		{platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072, x509.RSA, false},
	}
	for _, tc := range cases {
		keyAlgo, _, _, _, ecc, rsaCfg := ldevidAlgorithmParams(tc.algo)
		if keyAlgo != tc.keyAlgo {
			t.Errorf("algo %v: keyAlgo=%v want %v", tc.algo, keyAlgo, tc.keyAlgo)
		}
		if tc.ecc && ecc == nil {
			t.Errorf("algo %v: expected ECC config", tc.algo)
		}
		if !tc.ecc && rsaCfg == nil {
			t.Errorf("algo %v: expected RSA config", tc.algo)
		}
	}
}
