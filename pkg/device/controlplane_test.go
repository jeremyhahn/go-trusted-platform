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
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// fakeControlPlaneTPM answers exactly what the platform TPM answers, with
// every read individually failable so the registrar's best-effort and
// fail-closed halves can be told apart.
type fakeControlPlaneTPM struct {
	ekCert    *x509.Certificate
	ekErr     error
	iakCert   *x509.Certificate
	iakErr    error
	idevid    *x509.Certificate
	idevidErr error

	iakAttrs    *xkmssdk.KeyAttributes
	iakAttrsErr error
	sgnAttrs    *xkmssdk.KeyAttributes
	sgnAttrsErr error

	eventLog    []byte
	eventLogErr error
}

func (f *fakeControlPlaneTPM) EKCertificate() (*x509.Certificate, error) {
	return f.ekCert, f.ekErr
}
func (f *fakeControlPlaneTPM) IAKCertificate() (*x509.Certificate, error) {
	return f.iakCert, f.iakErr
}
func (f *fakeControlPlaneTPM) IDevIDCertificate() (*x509.Certificate, error) {
	return f.idevid, f.idevidErr
}
func (f *fakeControlPlaneTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return f.iakAttrs, f.iakAttrsErr
}
func (f *fakeControlPlaneTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return f.sgnAttrs, f.sgnAttrsErr
}
func (f *fakeControlPlaneTPM) EventLog() ([]byte, error) { return f.eventLog, f.eventLogErr }

// tpmKeyAttributes wraps a public area the way the TPM hands it back from
// ReadPublic on a persistent handle: TPMAttributes.BPublic, whose Bytes()
// are the TPMT_PUBLIC the TCG-CSR-IDEVID carries.
func tpmKeyAttributes(t *testing.T, pub *ecdsa.PublicKey, attrs tpm2.TPMAObject) *xkmssdk.KeyAttributes {
	t.Helper()
	raw, err := hex.DecodeString(attestPubHex(pub, attrs))
	require.NoError(t, err)
	area, err := tpm2.Unmarshal[tpm2.TPMTPublic](raw)
	require.NoError(t, err)
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{BPublic: tpm2.New2B(*area)},
	}
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type controlPlaneFixture struct {
	tpm       *fakeControlPlaneTPM
	registrar *stubRegistrar
	iak       *ecdsa.PrivateKey
	idevid    *ecdsa.PrivateKey
}

func newControlPlaneFixture(t *testing.T) *controlPlaneFixture {
	t.Helper()
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idevid, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &controlPlaneFixture{
		tpm: &fakeControlPlaneTPM{
			ekCert:   selfSignedTestCert(t, "ek-lab-node-2"),
			iakCert:  selfSignedTestIAKCert(t, "iak-SuperMicro X10SDV-SN-CP-1"),
			idevid:   selfSignedTestCert(t, "lab-node-2-idevid"),
			iakAttrs: tpmKeyAttributes(t, &iak.PublicKey, iakAttrs),
			sgnAttrs: tpmKeyAttributes(t, &idevid.PublicKey, tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
				UserWithAuth: true, SignEncrypt: true,
			}),
			eventLog: []byte("binary_bios_measurements"),
		},
		registrar: newStubRegistrar(),
		iak:       iak,
		idevid:    idevid,
	}
}

func (f *controlPlaneFixture) registrarFor(t *testing.T) *ControlPlaneRegistrar {
	t.Helper()
	r, err := NewControlPlaneRegistrar(ControlPlaneRegistrarConfig{
		TPM:     f.tpm,
		Devices: f.registrar,
		Model:   "SuperMicro X10SDV",
		Serial:  "SN-CP-1",
		Logger:  quietTestLogger(),
	})
	require.NoError(t, err)
	return r
}

func TestControlPlaneRegistrar_WritesTheSameRecordAnEnrollmentWould(t *testing.T) {
	f := newControlPlaneFixture(t)
	result, err := f.registrarFor(t).Register(context.Background())
	require.NoError(t, err)
	require.True(t, result.Created)

	dev := result.Device
	assert.Equal(t, "SuperMicro X10SDV", dev.Model)
	assert.Equal(t, "SN-CP-1", dev.Serial)
	assert.Equal(t, "lab-node-2-idevid", dev.Hostname, "the hostname is the IDevID Common Name")
	assert.Equal(t, EncodeCertificatePEM(f.tpm.ekCert), dev.EKCert)
	assert.Equal(t, EncodeCertificatePEM(f.tpm.iakCert), dev.AttestCert)
	assert.Equal(t, []byte("binary_bios_measurements"), dev.EventLog)
	assert.Equal(t, entities.DeviceStateRegistered, dev.State)

	// The recorded public area is the one the quote verifier parses back,
	// and it certifies the control plane's own attestation key.
	area, err := vm.ParseAKPublicArea(mustDecodeHex(t, dev.AttestPub))
	require.NoError(t, err)
	assert.True(t, area.Restricted)
	assert.True(t, area.SignEncrypt)
	require.NoError(t, area.VerifyRestrictedSigningKey())
	assert.True(t, publicKeysEqual(&f.iak.PublicKey, area.PublicKey))

	signing, err := vm.ParseAKPublicArea(mustDecodeHex(t, dev.SigningPub))
	require.NoError(t, err)
	assert.True(t, publicKeysEqual(&f.idevid.PublicKey, signing.PublicKey))
}

func TestControlPlaneRegistrar_IsIdempotentAcrossRestarts(t *testing.T) {
	f := newControlPlaneFixture(t)
	r := f.registrarFor(t)

	first, err := r.Register(context.Background())
	require.NoError(t, err)
	require.True(t, first.Created)

	second, err := r.Register(context.Background())
	require.NoError(t, err)
	assert.False(t, second.Created, "a restart re-uses the record it wrote")
	assert.Equal(t, first.Device.ID, second.Device.ID)
	assert.Len(t, f.registrar.saved, 1)
	assert.Len(t, f.registrar.updated, 1)
}

func TestControlPlaneRegistrar_RefusesWithoutAnAttestationKey(t *testing.T) {
	for name, mutate := range map[string]func(*fakeControlPlaneTPM){
		"no attributes":  func(tpm *fakeControlPlaneTPM) { tpm.iakAttrs = nil },
		"empty TPM area": func(tpm *fakeControlPlaneTPM) { tpm.iakAttrs = &xkmssdk.KeyAttributes{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newControlPlaneFixture(t)
			mutate(f.tpm)
			_, err := f.registrarFor(t).Register(context.Background())
			assert.ErrorAs(t, err, &ErrControlPlaneNoAttestationKey{})
			assert.Empty(t, f.registrar.saved, "no record is written for a machine nothing can verdict")
		})
	}
}

func TestControlPlaneRegistrar_AttestationKeyReadFailureIsReported(t *testing.T) {
	f := newControlPlaneFixture(t)
	f.tpm.iakAttrsErr = errors.New("handle 0x81010002 not found")

	_, err := f.registrarFor(t).Register(context.Background())
	var unavailable ErrControlPlaneIdentityUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "attestation key", unavailable.Name)
	assert.ErrorIs(t, err, f.tpm.iakAttrsErr)
	assert.Empty(t, f.registrar.saved)
}

func TestControlPlaneRegistrar_OptionalMaterialIsBestEffort(t *testing.T) {
	f := newControlPlaneFixture(t)
	f.tpm.ekErr = errors.New("no manufacturer EK certificate")
	f.tpm.iakErr = errors.New("no IAK certificate in the TPM store")
	f.tpm.idevidErr = errors.New("no IDevID certificate")
	f.tpm.sgnAttrsErr = errors.New("handle 0x81020000 not found")
	f.tpm.eventLogErr = errors.New("securityfs not mounted")

	result, err := f.registrarFor(t).Register(context.Background())
	require.NoError(t, err, "a TPM with no certificates still has an attestable key")
	assert.Equal(t, "", result.Device.EKCert)
	assert.Equal(t, "", result.Device.AttestCert)
	assert.Equal(t, "", result.Device.Hostname)
	assert.Equal(t, "", result.Device.SigningPub)
	assert.Empty(t, result.Device.EventLog)
	assert.NotEmpty(t, result.Device.AttestPub)
}

func TestControlPlaneRegistrar_StorageFailureIsReturned(t *testing.T) {
	f := newControlPlaneFixture(t)
	f.registrar.saveErr = errors.New("datastore unavailable")

	_, err := f.registrarFor(t).Register(context.Background())
	var saveErr ErrRegistrationSaveFailed
	assert.ErrorAs(t, err, &saveErr)
}

func TestNewControlPlaneRegistrar_FailsClosedOnMissingDependencies(t *testing.T) {
	f := newControlPlaneFixture(t)

	_, err := NewControlPlaneRegistrar(ControlPlaneRegistrarConfig{Devices: f.registrar, Serial: "SN-1"})
	assert.ErrorAs(t, err, &ErrControlPlaneNoTPM{})

	_, err = NewControlPlaneRegistrar(ControlPlaneRegistrarConfig{TPM: f.tpm, Serial: "SN-1"})
	assert.ErrorAs(t, err, &ErrRegistrationNoRegistrar{})

	_, err = NewControlPlaneRegistrar(ControlPlaneRegistrarConfig{TPM: f.tpm, Devices: f.registrar, Serial: " "})
	assert.ErrorAs(t, err, &ErrRegistrationNoSerial{})
}

func TestNewControlPlaneRegistrar_DefaultsClockAndLogger(t *testing.T) {
	f := newControlPlaneFixture(t)
	r, err := NewControlPlaneRegistrar(ControlPlaneRegistrarConfig{
		TPM: f.tpm, Devices: f.registrar, Serial: "SN-CP-1",
	})
	require.NoError(t, err)
	require.NotNil(t, r.logger)
	require.NotNil(t, r.now)
	assert.WithinDuration(t, time.Now().UTC(), r.now(), time.Minute)
}

// mustDecodeHex reads back a hex-encoded public area from a device record.
func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestControlPlaneRegistrar_LegacyIAKCertificateIsNotRecorded is the #472
// follow-up defect in its own right: the live fleet's control-plane IAK
// certificate was issued by a pre-0.9.4 CA and carries no
// tcg-cap-verifiedTPMRestricted. Recording it would make the control
// plane's first self-collection a cryptographic failure, and the
// attestation service dispatches a cryptographic verdict to the quarantine
// observers — the control plane would quarantine itself.
func TestControlPlaneRegistrar_LegacyIAKCertificateIsNotRecorded(t *testing.T) {
	f := newControlPlaneFixture(t)
	f.tpm.iakCert = selfSignedTestLegacyIAKCert(t, "iak-SuperMicro X10SDV-SN-CP-1")

	result, err := f.registrarFor(t).Register(context.Background())
	require.NoError(t, err, "the control plane is still a device; only the certificate is dropped")
	assert.Empty(t, result.Device.AttestCert,
		"an unverifiable certificate would quarantine the control plane on its first collection")
	assert.Equal(t, AttestCertNotRestrictedWarning, result.AttestCertWarning)

	// Everything else the enrollment proves is still recorded, so the record
	// is exactly the "denied service, not quarantined" shape.
	assert.NotEmpty(t, result.Device.AttestPub)
	assert.NotEmpty(t, result.Device.EKCert)
	assert.Equal(t, "lab-node-2-idevid", result.Device.Hostname)
}

func TestControlPlaneRegistrar_CompliantIAKCertificateIsRecorded(t *testing.T) {
	f := newControlPlaneFixture(t)
	result, err := f.registrarFor(t).Register(context.Background())
	require.NoError(t, err)
	assert.Equal(t, EncodeCertificatePEM(f.tpm.iakCert), result.Device.AttestCert)
	assert.Empty(t, result.AttestCertWarning)
}
