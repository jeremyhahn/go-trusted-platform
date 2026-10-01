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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// stubRegistrar is a Registrar whose every step is observable and
// individually failable.
type stubRegistrar struct {
	bySerial  map[string]*entities.Device
	findErr   error
	saveErr   error
	updateErr error
	saved     []*entities.Device
	updated   []*entities.Device
	// mismatch makes FindBySerial return a record whose serial disagrees
	// with the query, which is what an incomplete qrdb secondary index does.
	mismatch *entities.Device
}

func newStubRegistrar() *stubRegistrar {
	return &stubRegistrar{bySerial: map[string]*entities.Device{}}
}

func (s *stubRegistrar) FindBySerial(_ context.Context, serial string) (*entities.Device, error) {
	if s.findErr != nil {
		return nil, s.findErr
	}
	if s.mismatch != nil {
		return s.mismatch, nil
	}
	dev, ok := s.bySerial[serial]
	if !ok {
		return nil, errors.New("device not found")
	}
	return dev, nil
}

func (s *stubRegistrar) Save(_ context.Context, dev *entities.Device) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, dev)
	s.bySerial[dev.Serial] = dev
	return nil
}

func (s *stubRegistrar) Update(_ context.Context, dev *entities.Device) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updated = append(s.updated, dev)
	s.bySerial[dev.Serial] = dev
	return nil
}

func fullRegistration(t *testing.T) Registration {
	t.Helper()
	return Registration{
		Model:         "SuperMicro X10SDV",
		Serial:        "SN-CP-1",
		Hostname:      "node-02",
		EKCertPEM:     EncodeCertificatePEM(selfSignedTestCert(t, "ek")),
		AttestCertPEM: EncodeCertificatePEM(selfSignedTestIAKCert(t, "iak")),
		AttestPub:     []byte{0x00, 0x23, 0x01},
		SigningPub:    []byte{0x00, 0x23, 0x02},
		EventLog:      []byte("event-log"),
	}
}

// selfSignedTestCert issues a throwaway certificate valid around the
// current clock. Nothing here pins a wall-clock date: a fixture whose
// validity window is written as a literal expires silently (#506).
func selfSignedTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return selfSignedTestCertWithPolicies(t, cn, nil)
}

// selfSignedTestIAKCert issues a compliant attestation certificate: one
// carrying tcg-cap-verifiedTPMRestricted, which is what a CA at 0.9.4 or
// later stamps and what the registration will record.
func selfSignedTestIAKCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return selfSignedTestCertWithPolicies(t, cn, restrictedPolicies)
}

// selfSignedTestLegacyIAKCert issues what the live fleet's pre-0.9.4 CA
// stamped: residency and fixed attributes, no verifiedTPMRestricted.
func selfSignedTestLegacyIAKCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return selfSignedTestCertWithPolicies(t, cn, unrestrictedPolicies)
}

func selfSignedTestCertWithPolicies(t *testing.T, cn string, policies []x509.OID) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Policies:     policies,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestRegister_CreatesTheRecordFromTheEnrollment(t *testing.T) {
	reg := fullRegistration(t)
	registrar := newStubRegistrar()
	now := time.Now().UTC().Truncate(time.Second)

	result, err := Register(context.Background(), registrar, reg, now)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Created)
	require.Len(t, registrar.saved, 1)
	assert.Empty(t, registrar.updated)

	dev := result.Device
	assert.NotZero(t, dev.ID)
	assert.Equal(t, reg.Model, dev.Model)
	assert.Equal(t, reg.Serial, dev.Serial)
	assert.Equal(t, reg.Hostname, dev.Hostname)
	assert.Equal(t, reg.EKCertPEM, dev.EKCert)
	assert.Equal(t, reg.AttestCertPEM, dev.AttestCert)
	assert.Equal(t, hex.EncodeToString(reg.AttestPub), dev.AttestPub)
	assert.Equal(t, hex.EncodeToString(reg.SigningPub), dev.SigningPub)
	assert.Equal(t, reg.EventLog, dev.EventLog)
	assert.Equal(t, entities.DeviceStateRegistered, dev.State)
	assert.Equal(t, now, dev.CreatedAt)
	assert.Equal(t, now, dev.UpdatedAt)
}

func TestRegister_UpdatesTheExistingRecordAndKeepsItsID(t *testing.T) {
	registrar := newStubRegistrar()
	existing := &entities.Device{
		ID:        7,
		Serial:    "SN-CP-1",
		Model:     "old-model",
		EventLog:  []byte("old-log"),
		State:     entities.DeviceStateAttested,
		CreatedAt: time.Now().Add(-72 * time.Hour),
	}
	registrar.bySerial[existing.Serial] = existing

	reg := fullRegistration(t)
	result, err := Register(context.Background(), registrar, reg, time.Now().UTC())
	require.NoError(t, err)
	assert.False(t, result.Created)
	assert.Empty(t, result.LookupWarning, "an ordinary re-enrollment warns about nothing")
	assert.Empty(t, registrar.saved)
	require.Len(t, registrar.updated, 1)
	assert.Equal(t, uint64(7), result.Device.ID, "re-enrollment never allocates a second record")
	assert.Equal(t, reg.Model, result.Device.Model)
	assert.Equal(t, reg.EventLog, result.Device.EventLog)
}

func TestRegister_EmptyMaterialNeverErasesWhatIsRecorded(t *testing.T) {
	registrar := newStubRegistrar()
	registrar.bySerial["SN-CP-1"] = &entities.Device{
		ID:         7,
		Serial:     "SN-CP-1",
		Hostname:   "node-02",
		EKCert:     "EK-PEM",
		AttestCert: "IAK-PEM",
		AttestPub:  "aabb",
		SigningPub: "ccdd",
		EventLog:   []byte("log"),
	}

	_, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1", Model: "SuperMicro X10SDV"}, time.Now().UTC())
	require.NoError(t, err)

	dev := registrar.bySerial["SN-CP-1"]
	assert.Equal(t, "node-02", dev.Hostname)
	assert.Equal(t, "EK-PEM", dev.EKCert)
	assert.Equal(t, "IAK-PEM", dev.AttestCert)
	assert.Equal(t, "aabb", dev.AttestPub)
	assert.Equal(t, "ccdd", dev.SigningPub)
	assert.Equal(t, []byte("log"), dev.EventLog)
}

func TestRegister_MismatchedIndexHitBecomesACreate(t *testing.T) {
	registrar := newStubRegistrar()
	// What an incomplete qrdb secondary index returns: some other record.
	registrar.mismatch = &entities.Device{ID: 99, Serial: "SOMEONE-ELSE"}

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1", AttestPub: []byte{1}}, time.Now().UTC())
	require.NoError(t, err)
	assert.True(t, result.Created)
	assert.NotEqual(t, uint64(99), result.Device.ID)
	assert.Equal(t, "SN-CP-1", result.Device.Serial)
	assert.Contains(t, result.LookupWarning, "SOMEONE-ELSE",
		"the caller must be able to log why the index hit was discarded")
}

func TestRegister_LookupFailureFallsThroughToCreate(t *testing.T) {
	registrar := newStubRegistrar()
	registrar.findErr = errors.New("kv backend unavailable")

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1"}, time.Now().UTC())
	require.NoError(t, err, "a lookup failure must not abandon a device the CA just certified")
	assert.True(t, result.Created)
	assert.Contains(t, result.LookupWarning, "kv backend unavailable")
}

func TestRegister_RefusesWithoutARegistrar(t *testing.T) {
	_, err := Register(context.Background(), nil, Registration{Serial: "SN-1"}, time.Now().UTC())
	assert.ErrorAs(t, err, &ErrRegistrationNoRegistrar{})
}

func TestRegister_RefusesWithoutASerial(t *testing.T) {
	registrar := newStubRegistrar()
	_, err := Register(context.Background(), registrar, Registration{Serial: "   "}, time.Now().UTC())
	assert.ErrorAs(t, err, &ErrRegistrationNoSerial{})
	assert.Empty(t, registrar.saved)
}

func TestRegister_SaveFailureIsReportedAndNothingIsClaimed(t *testing.T) {
	registrar := newStubRegistrar()
	registrar.saveErr = errors.New("write refused")

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1"}, time.Now().UTC())
	assert.Nil(t, result)
	var saveErr ErrRegistrationSaveFailed
	require.ErrorAs(t, err, &saveErr)
	assert.Equal(t, "SN-CP-1", saveErr.Serial)
	assert.ErrorIs(t, err, registrar.saveErr)
	// The message the ACME finalize hook's contract test asserts on.
	assert.Contains(t, err.Error(), "device registration: failed to save device")
}

func TestRegister_UpdateFailureIsReported(t *testing.T) {
	registrar := newStubRegistrar()
	registrar.bySerial["SN-CP-1"] = &entities.Device{ID: 7, Serial: "SN-CP-1"}
	registrar.updateErr = errors.New("write refused")

	_, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1"}, time.Now().UTC())
	var updErr ErrRegistrationUpdateFailed
	require.ErrorAs(t, err, &updErr)
	assert.Equal(t, "SN-CP-1", updErr.Serial)
	assert.ErrorIs(t, err, registrar.updateErr)
}

func TestRegister_ZeroClockFallsBackToNow(t *testing.T) {
	registrar := newStubRegistrar()
	before := time.Now().UTC().Add(-time.Second)

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1"}, time.Time{})
	require.NoError(t, err)
	assert.False(t, result.Device.CreatedAt.IsZero())
	assert.True(t, result.Device.CreatedAt.After(before))
}

func TestEncodeCertificatePEM(t *testing.T) {
	cert := selfSignedTestCert(t, "encode")
	pemStr := EncodeCertificatePEM(cert)
	assert.Contains(t, pemStr, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, pemStr, EncodeCertificateDERPEM(cert.Raw))
}

func TestEncodeCertificatePEM_NothingToEncode(t *testing.T) {
	assert.Equal(t, "", EncodeCertificatePEM(nil))
	assert.Equal(t, "", EncodeCertificatePEM(&x509.Certificate{}))
	assert.Equal(t, "", EncodeCertificateDERPEM(nil))
	assert.Equal(t, "", EncodeCertificateDERPEM([]byte{}))
}

func TestIsRecordNotFound(t *testing.T) {
	assert.False(t, IsRecordNotFound(nil))
	assert.True(t, IsRecordNotFound(errors.New("device not found")))
	assert.True(t, IsRecordNotFound(errors.New("no such key")))
	assert.True(t, IsRecordNotFound(errors.New("entity does not exist")))
	assert.True(t, IsRecordNotFound(errors.New("no rows in result set")))
	assert.False(t, IsRecordNotFound(errors.New("connection refused")))
}

// The attestation-certificate gate (#472 follow-up). The device quote
// verifier treats a MISSING certificate as an absent check (denied service)
// and a PRESENT one that fails verification as a cryptographic failure,
// which quarantines the device. Recording a certificate the platform cannot
// verify therefore converts "cannot be attested" into "attestation failed",
// and the machine takes itself off the network.

func TestRegister_RecordsACompliantAttestationCertificate(t *testing.T) {
	registrar := newStubRegistrar()
	cert := EncodeCertificatePEM(selfSignedTestIAKCert(t, "iak-compliant"))

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1", AttestCertPEM: cert}, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, cert, result.Device.AttestCert)
	assert.Empty(t, result.AttestCertWarning)
}

func TestRegister_RefusesAnAttestationCertificateWithoutTheRestrictedPolicy(t *testing.T) {
	registrar := newStubRegistrar()
	legacy := EncodeCertificatePEM(selfSignedTestLegacyIAKCert(t, "iak-legacy"))

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1", AttestCertPEM: legacy, AttestPub: []byte{1}}, time.Now().UTC())
	require.NoError(t, err, "the device is still registered; only the certificate is dropped")
	assert.Empty(t, result.Device.AttestCert,
		"recording it would make the next collection a cryptographic failure and quarantine the device")
	assert.NotEmpty(t, result.Device.AttestPub, "the rest of the enrollment is recorded")
	assert.Equal(t, AttestCertNotRestrictedWarning, result.AttestCertWarning)
	assert.Contains(t, result.AttestCertWarning, "tcg-cap-verifiedTPMRestricted")
	assert.Contains(t, result.AttestCertWarning, "device attest-cert record --reissue")
}

func TestRegister_ARefusedCertificatePreservesTheOneAlreadyRecorded(t *testing.T) {
	registrar := newStubRegistrar()
	good := EncodeCertificatePEM(selfSignedTestIAKCert(t, "iak-good"))
	registrar.bySerial["SN-CP-1"] = &entities.Device{ID: 7, Serial: "SN-CP-1", AttestCert: good}

	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1",
			AttestCertPEM: EncodeCertificatePEM(selfSignedTestLegacyIAKCert(t, "iak-legacy"))},
		time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, good, result.Device.AttestCert,
		"a re-enrollment offering a worse certificate never replaces a verifiable one")
	assert.Equal(t, AttestCertNotRestrictedWarning, result.AttestCertWarning)
}

func TestRegister_RefusesAnUnparseableAttestationCertificate(t *testing.T) {
	for name, offered := range map[string]string{
		"not PEM":     "this is not a certificate",
		"wrong block": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"bad DER":     "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			registrar := newStubRegistrar()
			result, err := Register(context.Background(), registrar,
				Registration{Serial: "SN-CP-1", AttestCertPEM: offered}, time.Now().UTC())
			require.NoError(t, err)
			assert.Empty(t, result.Device.AttestCert,
				"the verifier fails an unparseable certificate too, which quarantines")
			assert.NotEmpty(t, result.AttestCertWarning)
		})
	}
}

func TestRegister_NoCertificateOfferedWarnsAboutNothing(t *testing.T) {
	registrar := newStubRegistrar()
	result, err := Register(context.Background(), registrar,
		Registration{Serial: "SN-CP-1", AttestPub: []byte{1}}, time.Now().UTC())
	require.NoError(t, err)
	assert.Empty(t, result.AttestCertWarning)
	assert.Empty(t, result.Device.AttestCert)
}
