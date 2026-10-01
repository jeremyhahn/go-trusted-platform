// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

var (
	attestCertTestNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	// The policy arcs come from the SDK re-export, the same source the
	// production check reads.
	oidTCGResidency  = quicbaasca.TCGVerifiedTPMResidencyPolicy
	oidTCGFixed      = quicbaasca.TCGVerifiedTPMFixedPolicy
	oidTCGRestricted = quicbaasca.TCGVerifiedTPMRestrictedPolicy

	// unrestrictedPolicies is what the fleet's CA stamped at enrollment
	// (2026-08-31): residency and fixed attributes, no verifiedTPMRestricted.
	unrestrictedPolicies = []x509.OID{oidTCGResidency, oidTCGFixed}
	// restrictedPolicies is what a compliant CA stamps.
	restrictedPolicies = []x509.OID{oidTCGResidency, oidTCGFixed, oidTCGRestricted}
)

// testCA is a fake platform CA: a self-signed root, a CN-keyed certificate
// store, and an attestation-key issuer whose policy set the test chooses.
type testCA struct {
	root      *x509.Certificate
	key       *ecdsa.PrivateKey
	store     map[string][]byte
	rootErr   error
	issueErr  error
	revokeErr error
	revoked   []string
	// issuePolicies is what IssueAKCertificate stamps; nil issues nothing.
	issuePolicies []x509.OID
	issued        []*quicbaasca.CACertificateRequest
	issuedKeys    []crypto.PublicKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca01.cp.test", Organization: []string{"Test Org"}},
		NotBefore:             attestCertTestNow.Add(-time.Hour),
		NotAfter:              attestCertTestNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{root: root, key: key, store: map[string][]byte{}}
}

// issue signs a certificate over pub with the given subject and policies.
func (c *testCA) issue(t *testing.T, cn string, org string, pub crypto.PublicKey, policies []x509.OID) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    attestCertTestNow.Add(-time.Minute),
		NotAfter:     attestCertTestNow.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Policies:     policies,
	}
	if org != "" {
		tmpl.Subject.Organization = []string{org}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, pub, c.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func (c *testCA) CertificatePEM(_ context.Context, cn string) ([]byte, error) {
	pemBytes, ok := c.store[cn]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return pemBytes, nil
}

func (c *testCA) IssueAKCertificate(_ context.Context, req *quicbaasca.CACertificateRequest, pub crypto.PublicKey) (*x509.Certificate, error) {
	c.issued = append(c.issued, req)
	c.issuedKeys = append(c.issuedKeys, pub)
	if c.issueErr != nil {
		return nil, c.issueErr
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:    attestCertTestNow.Add(-time.Minute),
		NotAfter:     attestCertTestNow.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Policies:     c.issuePolicies,
	}
	if req.Subject.Organization != "" {
		tmpl.Subject.Organization = []string{req.Subject.Organization}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, pub, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// xkms stores what it issues, keyed by CN.
	c.store[cert.Subject.CommonName] = certPEM(cert)
	return cert, nil
}

func (c *testCA) TrustedRoot() (*x509.Certificate, error) {
	if c.rootErr != nil {
		return nil, c.rootErr
	}
	return c.root, nil
}

func (c *testCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }

func (c *testCA) Revoke(_ context.Context, serial *big.Int, reason int) error {
	if c.revokeErr != nil {
		return c.revokeErr
	}
	c.revoked = append(c.revoked, fmt.Sprintf("%s/%d", serial.String(), reason))
	return nil
}

// readerCA is a testCA that also offers the IAKCertificateReader the CA
// gains with go-xkms#371: the IAK under iak-<model>-<serial>.
type readerCA struct {
	*testCA
	iak     *x509.Certificate
	readErr error
	reads   []string
}

func (c *readerCA) IAKCertificate(_ context.Context, model, serial string) (*x509.Certificate, error) {
	c.reads = append(c.reads, model+"/"+serial)
	if c.readErr != nil {
		return nil, c.readErr
	}
	return c.iak, nil
}

type testAuditor struct {
	events []verdict.AttestCertEvent
	err    error
}

func (a *testAuditor) RecordAttestCert(_ context.Context, e verdict.AttestCertEvent) error {
	a.events = append(a.events, e)
	return a.err
}

var iakAttrs = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	Restricted:          true,
	SignEncrypt:         true,
}

// attestPubHex encodes an ECC P-256 public key as the hex TPMT_PUBLIC the
// enrollment hook records in Device.AttestPub.
func attestPubHex(pub *ecdsa.PublicKey, attrs tpm2.TPMAObject) string {
	point, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	area := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: point[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: point[33:65]},
		}),
	}
	return hex.EncodeToString(tpm2.Marshal(area))
}

type recorderFixture struct {
	ctx      context.Context
	devices  *Service
	ca       *testCA
	audit    *testAuditor
	recorder *AttestCertRecorder
	iak      *ecdsa.PrivateKey
	device   *entities.Device
}

// newRecorderFixture registers a device the way a pre-#447 enrollment left
// it: model, serial, hostname and the IAK public area recorded, no
// certificate.
func newRecorderFixture(t *testing.T) *recorderFixture {
	t.Helper()
	svc, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dev := &entities.Device{
		ID:        42,
		Model:     "SuperMicro X10",
		Serial:    "SN0042",
		Hostname:  "node-03",
		AttestPub: attestPubHex(&iak.PublicKey, iakAttrs),
	}
	ctx := context.Background()
	require.NoError(t, svc.Save(ctx, dev))

	ca := newTestCA(t)
	audit := &testAuditor{}
	rec, err := NewAttestCertRecorder(svc, ca,
		WithAttestCertAuditor(audit),
		WithAttestCertClock(func() time.Time { return attestCertTestNow }),
	)
	require.NoError(t, err)
	return &recorderFixture{ctx: ctx, devices: svc, ca: ca, audit: audit, recorder: rec, iak: iak, device: dev}
}

func (f *recorderFixture) stored(t *testing.T) *entities.Device {
	t.Helper()
	dev, err := f.devices.Get(f.ctx, f.device.ID)
	require.NoError(t, err)
	return dev
}

func (f *recorderFixture) lastEvent(t *testing.T) verdict.AttestCertEvent {
	t.Helper()
	require.NotEmpty(t, f.audit.events, "an audit event is emitted for every attempt")
	return f.audit.events[len(f.audit.events)-1]
}

func TestNewAttestCertRecorder_RequiresDependencies(t *testing.T) {
	svc, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)

	_, err = NewAttestCertRecorder(nil, newTestCA(t))
	var dep ErrAttestCertRecorderDependency
	require.True(t, errors.As(err, &dep))
	assert.Equal(t, "device service", dep.Name)

	_, err = NewAttestCertRecorder(svc, nil)
	require.True(t, errors.As(err, &dep))
	assert.Equal(t, "certificate authority", dep.Name)

	rec, err := NewAttestCertRecorder(svc, newTestCA(t))
	require.NoError(t, err)
	assert.NotNil(t, rec)
}

func TestAttestCertRecorder_Record_InvalidAndUnknownDevice(t *testing.T) {
	f := newRecorderFixture(t)

	_, err := f.recorder.Record(f.ctx, 0, false)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)

	_, err = f.recorder.Record(f.ctx, 9999, false)
	require.Error(t, err)
	assert.Empty(t, f.audit.events, "no device, no attempt to audit")
}

func TestAttestCertRecorder_RecordsCompliantCertificateFromCAStore(t *testing.T) {
	f := newRecorderFixture(t)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "Test Org", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)

	rec, err := f.recorder.Record(f.ctx, f.device.ID, false)
	require.NoError(t, err)
	assert.Equal(t, AttestCertSourceCA, rec.Source)
	assert.Equal(t, "SuperMicro X10-SN0042", rec.SourceDetail)
	assert.True(t, rec.Changed)
	assert.False(t, rec.Reissued)
	assert.Equal(t, cert.SerialNumber.String(), rec.CertificateSerial)
	assert.Equal(t, cert.NotAfter, rec.NotAfter)
	assert.Equal(t, string(certPEM(cert)), rec.CertificatePEM)

	stored := f.stored(t)
	assert.Equal(t, string(certPEM(cert)), stored.AttestCert, "the certificate is written to the device record")
	assert.Equal(t, f.device.AttestPub, stored.AttestPub, "the public area survives the write")

	// The verifier accepts exactly what was recorded, by construction.
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.root)
	pub, err := vm.VerifyAKCertificate([]byte(stored.AttestCert), roots, nil, attestCertTestNow)
	require.NoError(t, err)
	assert.True(t, f.iak.PublicKey.Equal(pub))

	ev := f.lastEvent(t)
	assert.True(t, ev.Recorded)
	assert.Equal(t, "ca", ev.Source)
	assert.Equal(t, uint64(42), ev.DeviceID)
	assert.Equal(t, "node-03", ev.HostID)
	assert.Equal(t, "SN0042", ev.Serial)
	assert.False(t, ev.Reissued)
	assert.Empty(t, ev.Reason)
	assert.Empty(t, f.ca.issued, "a stored certificate is never re-issued")
}

func TestAttestCertRecorder_ExistingCompliantCertificateIsUnchanged(t *testing.T) {
	f := newRecorderFixture(t)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "", &f.iak.PublicKey, restrictedPolicies)
	f.device.AttestCert = string(certPEM(cert))
	require.NoError(t, f.devices.Update(f.ctx, f.device))
	before := f.stored(t).UpdatedAt

	rec, err := f.recorder.Record(f.ctx, f.device.ID, true)
	require.NoError(t, err)
	assert.Equal(t, AttestCertSourceDevice, rec.Source)
	assert.False(t, rec.Changed)
	assert.Equal(t, before, f.stored(t).UpdatedAt, "nothing is written when the record already holds the certificate")
	assert.Empty(t, f.ca.issued, "reissue is not consulted when the record is already compliant")
	assert.True(t, f.lastEvent(t).Recorded)
}

// TestAttestCertRecorder_UnrestrictedCertificateIsRefused is the case the
// verb exists to prevent: the fleet's enrollment-time IAK certificates chain
// to the CA but lack tcg-cap-verifiedTPMRestricted, and recording one would
// quarantine the node on its next quote. Mutation check: removing the
// attribute check from vm.VerifyAKCertificate makes this test fail.
func TestAttestCertRecorder_UnrestrictedCertificateIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "", &f.iak.PublicKey, unrestrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)

	rec, err := f.recorder.Record(f.ctx, f.device.ID, false)
	assert.Nil(t, rec)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	var notRestricted vm.ErrAKCertificateNotRestricted
	assert.True(t, errors.As(err, &notRestricted), "the refusal names the missing attribute: %v", err)
	assert.False(t, refused.Reissued)

	assert.Empty(t, f.stored(t).AttestCert, "a refused certificate is never written")
	ev := f.lastEvent(t)
	assert.False(t, ev.Recorded)
	assert.Contains(t, ev.Reason, "tcg-cap-verifiedTPMRestricted")
}

func TestAttestCertRecorder_UntrustedIssuerIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	other := newTestCA(t)
	cert := other.issue(t, "SuperMicro X10-SN0042", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)

	_, err := f.recorder.Record(f.ctx, f.device.ID, false)
	var invalid vm.ErrAKCertificateInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Contains(t, invalid.Reason, "does not chain")
	assert.Empty(t, f.stored(t).AttestCert)
	assert.False(t, f.lastEvent(t).Recorded)
}

func TestAttestCertRecorder_GarbageCertificateIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	f.device.AttestCert = "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n"
	require.NoError(t, f.devices.Update(f.ctx, f.device))

	_, err := f.recorder.Record(f.ctx, f.device.ID, false)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	var invalid vm.ErrAKCertificateInvalid
	assert.True(t, errors.As(err, &invalid))
	// Every source is named in the refusal: the record and each CA name.
	assert.Len(t, refused.Attempts, 4)
	assert.Equal(t, AttestCertSourceDevice, refused.Attempts[0].Source)
	assert.Equal(t, f.device.AttestCert, f.stored(t).AttestCert, "the garbage stays as it was; nothing is rewritten")
}

func TestAttestCertRecorder_CertificateOverAnotherKeyIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "", &otherKey.PublicKey, restrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)

	_, err = f.recorder.Record(f.ctx, f.device.ID, false)
	var mismatch ErrAttestCertKeyMismatch
	require.True(t, errors.As(err, &mismatch), "got %v", err)
	assert.Empty(t, f.stored(t).AttestCert)
	assert.False(t, f.lastEvent(t).Recorded)
}

func TestAttestCertRecorder_NoAttestPubIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)
	// The DAO restores a zero AttestPub from the stored record, so clear it
	// through a fresh entity that carries every other field.
	stored := f.stored(t)
	stored.AttestPub = " "
	require.NoError(t, f.devices.Update(f.ctx, stored))

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var noPub ErrAttestCertNoAttestPub
	require.True(t, errors.As(err, &noPub), "got %v", err)
	assert.Equal(t, uint64(42), noPub.DeviceID)
	assert.Empty(t, f.stored(t).AttestCert, "a compliant certificate cannot be tied to a device without its key")
	assert.Empty(t, f.ca.issued, "re-issuance needs the enrolled key")
	assert.False(t, f.lastEvent(t).Recorded)
}

func TestAttestCertRecorder_UndecodableAttestPubIsRefused(t *testing.T) {
	f := newRecorderFixture(t)
	stored := f.stored(t)
	stored.AttestPub = "zz-not-hex"
	require.NoError(t, f.devices.Update(f.ctx, stored))

	_, err := f.recorder.Record(f.ctx, f.device.ID, false)
	var bad ErrAttestCertAttestPubInvalid
	require.True(t, errors.As(err, &bad), "got %v", err)

	stored.AttestPub = hex.EncodeToString([]byte{0x00, 0x01, 0x02})
	require.NoError(t, f.devices.Update(f.ctx, stored))
	_, err = f.recorder.Record(f.ctx, f.device.ID, false)
	require.True(t, errors.As(err, &bad), "got %v", err)
	var area vm.ErrAKPublicAreaInvalid
	assert.True(t, errors.As(err, &area))
}

func TestAttestCertRecorder_TrustAnchorUnavailableRefusesEverything(t *testing.T) {
	f := newRecorderFixture(t)
	cert := f.ca.issue(t, "SuperMicro X10-SN0042", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(cert)
	f.ca.rootErr = errors.New("ca sealed")

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var anchor ErrAttestCertTrustAnchorUnavailable
	require.True(t, errors.As(err, &anchor), "got %v", err)
	assert.Empty(t, f.stored(t).AttestCert)
	assert.Empty(t, f.ca.issued)
}

func TestAttestCertRecorder_NoCandidateWithoutReissueIsRefused(t *testing.T) {
	f := newRecorderFixture(t)

	_, err := f.recorder.Record(f.ctx, f.device.ID, false)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	assert.Len(t, refused.Attempts, 3, "every CA name was tried: %v", err)
	for _, a := range refused.Attempts {
		assert.Equal(t, AttestCertSourceCA, a.Source)
		var missing ErrAttestCertNotInStore
		assert.True(t, errors.As(a.Err, &missing))
	}
	assert.Empty(t, f.ca.issued, "the CA is never asked to issue without reissue")
	assert.Empty(t, f.stored(t).AttestCert)
	ev := f.lastEvent(t)
	assert.False(t, ev.Recorded)
	assert.False(t, ev.Reissued)
}

func TestAttestCertRecorder_ReissueRecordsWhenCAStampsRestricted(t *testing.T) {
	f := newRecorderFixture(t)
	// The CA store holds the IDevID under the enrollment subject: the
	// re-issued IAK copies its organisation and takes a distinct CN.
	idevid := f.ca.issue(t, "SuperMicro X10-SN0042", "Fleet Org", &f.iak.PublicKey, unrestrictedPolicies)
	f.ca.store["SuperMicro X10-SN0042"] = certPEM(idevid)
	f.ca.issuePolicies = restrictedPolicies

	rec, err := f.recorder.Record(f.ctx, f.device.ID, true)
	require.NoError(t, err)
	assert.Equal(t, AttestCertSourceReissued, rec.Source)
	assert.Equal(t, "iak-SuperMicro X10-SN0042", rec.SourceDetail)
	assert.True(t, rec.Changed)
	assert.True(t, rec.Reissued)
	assert.Contains(t, rec.Subject, "CN=iak-SuperMicro X10-SN0042")
	assert.Contains(t, rec.Subject, "O=Fleet Org")

	require.Len(t, f.ca.issued, 1)
	assert.Equal(t, "iak-SuperMicro X10-SN0042", f.ca.issued[0].Subject.CommonName)
	assert.Equal(t, "Fleet Org", f.ca.issued[0].Subject.Organization)
	assert.True(t, f.iak.PublicKey.Equal(f.ca.issuedKeys[0]), "the CA certifies the enrolled key, nothing else")

	stored := f.stored(t)
	assert.Equal(t, rec.CertificatePEM, stored.AttestCert)
	assert.NotEqual(t, string(certPEM(idevid)), stored.AttestCert, "the IDevID record in the CA store is not what gets recorded")

	ev := f.lastEvent(t)
	assert.True(t, ev.Recorded)
	assert.Equal(t, "reissued", ev.Source)
	assert.True(t, ev.Reissued)
}

// TestAttestCertRecorder_ReissueIsRefusedUntilCAStampsRestricted is the
// state of the fleet today: the CA re-issues, but from a profile without
// tcg-cap-verifiedTPMRestricted. The re-issued certificate is refused like
// any other and nothing is recorded.
func TestAttestCertRecorder_ReissueIsRefusedUntilCAStampsRestricted(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issuePolicies = unrestrictedPolicies

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	assert.True(t, refused.Reissued)
	var notRestricted vm.ErrAKCertificateNotRestricted
	assert.True(t, errors.As(err, &notRestricted))
	last := refused.Attempts[len(refused.Attempts)-1]
	assert.Equal(t, AttestCertSourceReissued, last.Source)

	assert.Len(t, f.ca.issued, 1)
	assert.Empty(t, f.stored(t).AttestCert, "the non-compliant re-issued certificate is not recorded")
	ev := f.lastEvent(t)
	assert.False(t, ev.Recorded)
	assert.True(t, ev.Reissued, "the audit says the CA was asked")
}

func TestAttestCertRecorder_ReissueRefusedForUnrestrictedPublicArea(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issuePolicies = restrictedPolicies
	attrs := iakAttrs
	attrs.Restricted = false
	stored := f.stored(t)
	stored.AttestPub = attestPubHex(&f.iak.PublicKey, attrs)
	require.NoError(t, f.devices.Update(f.ctx, stored))

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var notRestricted ErrAttestCertPublicAreaNotRestricted
	require.True(t, errors.As(err, &notRestricted), "got %v", err)
	var area vm.ErrAKPublicAreaNotRestricted
	assert.True(t, errors.As(err, &area))
	assert.Empty(t, f.ca.issued, "the CA is never asked to certify an unrestricted key as an attestation key")
	assert.Empty(t, f.stored(t).AttestCert)
	assert.False(t, f.lastEvent(t).Reissued)
}

func TestAttestCertRecorder_ReissueCAFailureIsReported(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issueErr = errors.New("issuer key unavailable")

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var failed ErrAttestCertReissueFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.ErrorIs(t, err, f.ca.issueErr)
	assert.Empty(t, f.stored(t).AttestCert)
	assert.True(t, f.lastEvent(t).Reissued)
}

func TestAttestCertRecorder_AuditFailureDoesNotUndoTheRecord(t *testing.T) {
	f := newRecorderFixture(t)
	f.audit.err = errors.New("event store full")
	cert := f.ca.issue(t, "node-03", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["node-03"] = certPEM(cert)

	rec, err := f.recorder.Record(f.ctx, f.device.ID, false)
	require.NoError(t, err)
	assert.Equal(t, "node-03", rec.SourceDetail, "the IDevID hostname is tried first")
	assert.Equal(t, string(certPEM(cert)), f.stored(t).AttestCert)
	assert.Len(t, f.audit.events, 1)
}

func TestAttestCertRecorder_WorksWithoutAuditor(t *testing.T) {
	f := newRecorderFixture(t)
	rec, err := NewAttestCertRecorder(f.devices, f.ca, WithAttestCertClock(func() time.Time { return attestCertTestNow }))
	require.NoError(t, err)
	cert := f.ca.issue(t, "node-03", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["node-03"] = certPEM(cert)

	got, err := rec.Record(f.ctx, f.device.ID, false)
	require.NoError(t, err)
	assert.True(t, got.Changed)
}

func TestAttestCertCandidateNames_OrderAndDedupe(t *testing.T) {
	names := attestCertCandidateNames(&entities.Device{Hostname: "node-03", Model: "SuperMicro X10", Serial: "SN1"})
	assert.Equal(t, []string{"node-03", "SuperMicro X10-SN1", "iak-SuperMicro X10-SN1"}, names)

	names = attestCertCandidateNames(&entities.Device{Hostname: "SuperMicro X10-SN1", Model: "SuperMicro X10", Serial: "SN1"})
	assert.Equal(t, []string{"SuperMicro X10-SN1", "iak-SuperMicro X10-SN1"}, names, "a hostname equal to the TCG subject is tried once")

	names = attestCertCandidateNames(&entities.Device{Serial: "SN1"})
	assert.Empty(t, names, "no model and no hostname gives the CA nothing to look up")
}

func TestErrAttestCertRefused_MessagesAndUnwrap(t *testing.T) {
	empty := ErrAttestCertRefused{DeviceID: 3}
	assert.Contains(t, empty.Error(), "pass reissue")
	assert.Empty(t, empty.Unwrap())

	inner := vm.ErrAKCertificateNotRestricted{Subject: "CN=x"}
	full := ErrAttestCertRefused{DeviceID: 3, Attempts: []AttestCertAttempt{
		{Source: AttestCertSourceCA, Detail: "node-03", Err: inner},
		{Source: AttestCertSourceDevice},
	}}
	assert.Contains(t, full.Error(), "ca[node-03]")
	assert.Contains(t, full.Error(), "nothing recorded")
	assert.Equal(t, []error{inner}, full.Unwrap())
}

func TestAttestCertRecorder_ReissueNeverUsesTheIDevIDCN(t *testing.T) {
	// The hostname equal to the TCG subject is the fleet's shape: the
	// IDevID CN, the TCG subject and the store key are all one name. The
	// re-issue request must still carry the distinct IAK name, or the CA's
	// CN-keyed store would overwrite the IDevID record (go-xkms#371).
	f := newRecorderFixture(t)
	stored := f.stored(t)
	stored.Hostname = "SuperMicro X10-SN0042"
	require.NoError(t, f.devices.Update(f.ctx, stored))
	f.ca.issuePolicies = restrictedPolicies

	rec, err := f.recorder.Record(f.ctx, f.device.ID, true)
	require.NoError(t, err)
	require.Len(t, f.ca.issued, 1)
	cn := f.ca.issued[0].Subject.CommonName
	assert.Equal(t, "iak-SuperMicro X10-SN0042", cn)
	assert.NotEqual(t, stored.Hostname, cn, "never the IDevID CN")
	assert.NotEqual(t, "SuperMicro X10-SN0042", cn, "never the TCG subject")
	assert.Equal(t, cn, rec.SourceDetail)
	_, idevidIntact := f.ca.store["SuperMicro X10-SN0042"]
	assert.False(t, idevidIntact, "nothing was stored under the IDevID name by this attempt")
	_, iakStored := f.ca.store[cn]
	assert.True(t, iakStored)
}

func TestAttestCertRecorder_RefusedReissueIsRevoked(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issuePolicies = unrestrictedPolicies

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	require.Len(t, f.ca.issued, 1)
	require.Len(t, f.ca.revoked, 1, "the non-compliant certificate the CA just stored is withdrawn")
	issued := parseFirstCertificate(f.ca.store["iak-SuperMicro X10-SN0042"])
	require.NotNil(t, issued)
	assert.Equal(t, issued.SerialNumber.String()+"/4", f.ca.revoked[0], "revoked by serial, reason superseded")
	assert.Empty(t, f.stored(t).AttestCert)
}

func TestAttestCertRecorder_RefusedReissueRevokeFailureIsReported(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issuePolicies = unrestrictedPolicies
	f.ca.revokeErr = errors.New("crl store sealed")

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var revokeFailed ErrAttestCertReissuedRevokeFailed
	require.True(t, errors.As(err, &revokeFailed), "got %v", err)
	assert.Equal(t, uint64(42), revokeFailed.DeviceID)
	assert.Contains(t, revokeFailed.Subject, "iak-SuperMicro X10-SN0042")
	assert.NotEmpty(t, revokeFailed.Serial)
	var notRestricted vm.ErrAKCertificateNotRestricted
	assert.True(t, errors.As(err, &notRestricted), "the refusal is still reachable")
	assert.ErrorIs(t, err, f.ca.revokeErr)
	assert.Contains(t, err.Error(), "revoke it by hand")
	assert.Empty(t, f.stored(t).AttestCert)
	ev := f.lastEvent(t)
	assert.False(t, ev.Recorded)
	assert.True(t, ev.Reissued)
	assert.Contains(t, ev.Reason, "could not revoke")
}

func TestAttestCertRecorder_UnrestrictedPublicAreaRefusalIsTypedAndAudited(t *testing.T) {
	f := newRecorderFixture(t)
	f.ca.issuePolicies = restrictedPolicies
	attrs := iakAttrs
	attrs.FixedTPM = false
	stored := f.stored(t)
	stored.AttestPub = attestPubHex(&f.iak.PublicKey, attrs)
	require.NoError(t, f.devices.Update(f.ctx, stored))

	_, err := f.recorder.Record(f.ctx, f.device.ID, true)
	var notRestricted ErrAttestCertPublicAreaNotRestricted
	require.True(t, errors.As(err, &notRestricted), "got %v", err)
	ev := f.lastEvent(t)
	assert.False(t, ev.Recorded)
	assert.False(t, ev.Reissued, "the CA was never asked")
	assert.Contains(t, ev.Reason, "fixedTPM")
	assert.Empty(t, f.ca.issued)
}

func TestAttestCertRecorder_PrefersTheIAKReaderWhenTheCAOffersIt(t *testing.T) {
	f := newRecorderFixture(t)
	iak := f.ca.issue(t, "iak-SuperMicro X10-SN0042", "", &f.iak.PublicKey, restrictedPolicies)
	rca := &readerCA{testCA: f.ca, iak: iak}
	rec, err := NewAttestCertRecorder(f.devices, rca,
		WithAttestCertAuditor(f.audit),
		WithAttestCertClock(func() time.Time { return attestCertTestNow }))
	require.NoError(t, err)

	got, err := rec.Record(f.ctx, f.device.ID, false)
	require.NoError(t, err)
	assert.Equal(t, AttestCertSourceCA, got.Source)
	assert.Equal(t, "iak-SuperMicro X10-SN0042", got.SourceDetail)
	assert.Equal(t, []string{"SuperMicro X10/SN0042"}, rca.reads)
	assert.Equal(t, string(certPEM(iak)), f.stored(t).AttestCert)
}

func TestAttestCertRecorder_IAKReaderMissFallsBackToCNLookups(t *testing.T) {
	f := newRecorderFixture(t)
	rca := &readerCA{testCA: f.ca, readErr: errors.New("not found")}
	cert := f.ca.issue(t, "node-03", "", &f.iak.PublicKey, restrictedPolicies)
	f.ca.store["node-03"] = certPEM(cert)
	rec, err := NewAttestCertRecorder(f.devices, rca, WithAttestCertClock(func() time.Time { return attestCertTestNow }))
	require.NoError(t, err)

	got, err := rec.Record(f.ctx, f.device.ID, false)
	require.NoError(t, err)
	assert.Equal(t, "node-03", got.SourceDetail)
	assert.Len(t, rca.reads, 1)

	// And a reader that returns the wrong key is refused like any candidate.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rca2 := &readerCA{testCA: newTestCA(t)}
	rca2.iak = rca2.issue(t, "iak-SuperMicro X10-SN0042", "", &other.PublicKey, restrictedPolicies)
	rec2, err := NewAttestCertRecorder(f.devices, rca2, WithAttestCertClock(func() time.Time { return attestCertTestNow }))
	require.NoError(t, err)
	stored := f.stored(t)
	stored.AttestCert = " "
	require.NoError(t, f.devices.Update(f.ctx, stored))
	_, err = rec2.Record(f.ctx, f.device.ID, false)
	var refused ErrAttestCertRefused
	require.True(t, errors.As(err, &refused), "got %v", err)
	var mismatch ErrAttestCertKeyMismatch
	assert.True(t, errors.As(err, &mismatch))
}
