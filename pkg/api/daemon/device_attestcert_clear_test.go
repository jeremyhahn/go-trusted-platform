package daemon

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// errNothingStored is the CA store miss of emptyStoreCA.
type errNothingStored struct{ cn string }

func (e errNothingStored) Error() string { return "nothing stored under " + e.cn }

// errNoIssuance is returned by emptyStoreCA for every issue or revoke.
type errNoIssuance struct{}

func (errNoIssuance) Error() string { return "this CA issues nothing" }

// emptyStoreCA is the platform CA of the quote fixture with an empty
// certificate store: the only candidate the recorder sees is the
// certificate already on the device record.
type emptyStoreCA struct{ trust *fakeAKTrust }

func (c emptyStoreCA) CertificatePEM(_ context.Context, cn string) ([]byte, error) {
	return nil, errNothingStored{cn: cn}
}

func (c emptyStoreCA) IssueAKCertificate(context.Context, *xkmsca.CACertificateRequest, crypto.PublicKey) (*x509.Certificate, error) {
	return nil, errNoIssuance{}
}

func (c emptyStoreCA) TrustedRoot() (*x509.Certificate, error) { return c.trust.TrustedRoot() }

func (c emptyStoreCA) TrustedIntermediate() (*x509.Certificate, error) {
	return c.trust.TrustedIntermediate()
}

func (c emptyStoreCA) Revoke(context.Context, *big.Int, int) error { return errNoIssuance{} }

// attestCertEvents captures what the recorder audits.
type attestCertEvents struct{ events []verdict.AttestCertEvent }

func (s *attestCertEvents) RecordAttestCert(_ context.Context, e verdict.AttestCertEvent) error {
	s.events = append(s.events, e)
	return nil
}

// TestClearOnRefusal_NextQuoteIsAnAbsenceNotACryptographicFailure is #516
// end to end: a device holding a certificate without
// tcg-cap-verifiedTPMRestricted is quarantined by every collection. Clearing
// it through the recorder turns the next collection into an absence —
// denied service, never quarantine — and leaves an audit event that names
// the clear.
func TestClearOnRefusal_NextQuoteIsAnAbsenceNotACryptographicFailure(t *testing.T) {
	f := newQuoteFixture(t)
	devices := newRealDeviceService(t)
	dev := &deviceentities.Device{
		Model:      f.device.Model,
		Serial:     f.device.Serial,
		Hostname:   f.device.Hostname,
		AttestPub:  hex.EncodeToString(rsaKeyAttributes(t, &f.key.PublicKey, true).TPMAttributes.BPublic.Bytes()),
		AttestCert: f.ca.issueAK(t, &f.key.PublicKey, false),
	}
	require.NoError(t, devices.Create(context.Background(), dev))
	deviceID := itoa(dev.ID)

	verifier := NewDeviceQuoteVerifier(devices, f.profiles, f.trust, f.sink, nil)
	verifier.now = func() time.Time { return f.now }
	collect := func(nonce string) {
		t.Helper()
		_, err := verifier.Verify(context.Background(), deviceID, f.evidence(t, []byte(nonce), goldenPCRs()))
		require.NoError(t, err)
	}

	collect("nonce-before")
	require.True(t, f.sink.last(t).Cryptographic, "the non-compliant certificate quarantines the device")

	audit := &attestCertEvents{}
	recorder, err := device.NewAttestCertRecorder(devices, emptyStoreCA{trust: f.trust}, device.WithAttestCertAuditor(audit))
	require.NoError(t, err)

	_, err = recorder.Record(context.Background(), dev.ID, device.AttestCertRecordOptions{})
	var refused device.ErrAttestCertRefused
	require.ErrorAs(t, err, &refused, "without the flag the refusal is returned unchanged")
	stored, err := devices.Get(context.Background(), dev.ID)
	require.NoError(t, err)
	require.Equal(t, dev.AttestCert, stored.AttestCert, "without the flag nothing is written")

	rec, err := recorder.Record(context.Background(), dev.ID, device.AttestCertRecordOptions{ClearOnRefusal: true})
	require.NoError(t, err)
	assert.True(t, rec.Cleared)
	stored, err = devices.Get(context.Background(), dev.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.AttestCert)

	require.Len(t, audit.events, 2)
	assert.False(t, audit.events[0].Cleared, "the refusal is audited as a refusal")
	assert.False(t, audit.events[0].Recorded)
	assert.True(t, audit.events[1].Cleared, "the clear is audited as a clear")
	assert.False(t, audit.events[1].Recorded)
	assert.Contains(t, strings.ToLower(audit.events[1].Reason), "restricted", "the event keeps why the certificate was refused")

	collect("nonce-after")
	dv := f.sink.last(t)
	assert.False(t, dv.Passed)
	assert.False(t, dv.Cryptographic, "THE property: after the clear the device is absent, not quarantined")
}
