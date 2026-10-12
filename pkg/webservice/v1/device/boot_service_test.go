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
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const bootDeviceID uint64 = 42

// bootPKI is a platform CA and an IDevID it issued.
type bootPKI struct {
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	caPEM    []byte
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	chainPEM string
}

func newBootPKI(t *testing.T) *bootPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "platform root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	pki := &bootPKI{
		caKey:  caKey,
		caCert: caCert,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}
	pki.leaf, pki.leafKey, pki.chainPEM = pki.issue(t, "node-1.example", x509.ExtKeyUsageClientAuth)
	return pki
}

func (p *bootPKI) issue(t *testing.T, cn string, eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) // leaf first
	chain = append(chain, p.caPEM...)
	return cert, key, string(chain)
}

type fakeBootDevices struct {
	dev *entities.Device
	err error
}

func (f *fakeBootDevices) ResolveIdentity(_ context.Context, identity string) (*entities.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.dev == nil || (identity != f.dev.Serial && identity != f.dev.Hostname) {
		return nil, &device.IdentityNotFoundError{Identity: identity, Cause: &MessageError{Msg: "no record"}}
	}
	copied := *f.dev
	return &copied, nil
}

type fakeBootProfiles struct {
	profile *entities.DeviceProfile
	err     error
}

func (f *fakeBootProfiles) FindProfileForDevice(context.Context, *entities.Device) (*entities.DeviceProfile, error) {
	return f.profile, f.err
}

type fakeBootCA struct {
	bundle []byte
	err    error
}

func (f *fakeBootCA) CABundle() ([]byte, error) { return f.bundle, f.err }

// bootFixture is one enrolled diskless node and a control plane that knows
// it, with every dependency answering yes; a test changes one thing.
type bootFixture struct {
	pki      *bootPKI
	devices  *fakeBootDevices
	profiles *fakeBootProfiles
	attestor *stubAttestDeviceService
	ca       *fakeBootCA
	nonce    []byte
	// serverRoots trusts the control plane's TLS server certificate; set by
	// startBootControlPlane.
	serverRoots *x509.CertPool
}

func newBootFixture(t *testing.T) *bootFixture {
	t.Helper()
	pki := newBootPKI(t)
	return &bootFixture{
		pki: pki,
		devices: &fakeBootDevices{dev: &entities.Device{
			ID:         bootDeviceID,
			Serial:     "SN-42",
			Hostname:   "node-1.example",
			State:      entities.DeviceStateAttested,
			IDevIDCert: pki.chainPEM,
			AttestCert: "iak-pem",
		}},
		profiles: &fakeBootProfiles{profile: &entities.DeviceProfile{}},
		attestor: &stubAttestDeviceService{resp: &platformv1.AttestDeviceResponse{
			DeviceId:          bootDeviceID,
			Verified:          true,
			PcrBaselineSource: "signed",
		}},
		ca:    &fakeBootCA{bundle: pki.caPEM},
		nonce: []byte("connection-exporter-value-32-byt"),
	}
}

func (f *bootFixture) service() *BootService {
	return NewBootService(f.devices, f.profiles, f.attestor, f.ca)
}

func (f *bootFixture) input(t *testing.T) BootDeliveryInput {
	return BootDeliveryInput{
		Identity:     "node-1.example",
		PeerLeaf:     f.pki.leaf,
		ChannelNonce: f.nonce,
		Evidence:     bootEvidence(t, f.nonce),
	}
}

func bootEvidence(t *testing.T, nonce []byte) []byte {
	t.Helper()
	evidence, err := json.Marshal(vm.QuoteEvidence{Quote: []byte("quote"), Signature: []byte("sig"), Nonce: nonce})
	require.NoError(t, err)
	return evidence
}

func TestBootService_Deliver_ReturnsThatDevicesMaterial(t *testing.T) {
	f := newBootFixture(t)

	resp, err := f.service().Deliver(context.Background(), f.input(t))
	require.NoError(t, err)

	assert.Equal(t, "SN-42", resp.Serial)
	assert.Equal(t, f.pki.chainPEM, resp.IDevIDChain)
	assert.Equal(t, "iak-pem", resp.AttestCert)
	assert.Equal(t, string(f.pki.caPEM), resp.CABundle)
	assert.Equal(t, "SN-42", resp.Profile.SerialNumber)
	assert.Equal(t, "signed", resp.PCRBaselineSource)
	assert.Equal(t, "42", f.attestor.gotDeviceID, "the quote is verified as the resolved device")
	assert.Equal(t, f.input(t).Evidence, f.attestor.gotEvidence, "the verifier sees the evidence unchanged")
}

func TestBootService_Deliver_QuarantinedNodeMayBoot(t *testing.T) {
	f := newBootFixture(t)
	f.devices.dev.State = entities.DeviceStateQuarantined

	_, err := f.service().Deliver(context.Background(), f.input(t))
	require.NoError(t, err, "remediation needs the node up to re-attest")
}

func TestBootService_Deliver_RefusesWhatIsNotTheEnrolledDeviceInAVerifiedState(t *testing.T) {
	cases := map[string]struct {
		mutate        func(t *testing.T, f *bootFixture, in *BootDeliveryInput)
		reachVerifier bool
	}{
		"another IDevID from the same CA": {mutate: func(t *testing.T, f *bootFixture, in *BootDeliveryInput) {
			in.PeerLeaf, _, _ = f.pki.issue(t, "node-1.example", x509.ExtKeyUsageClientAuth)
		}},
		"no client certificate": {mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) {
			in.PeerLeaf = nil
		}},
		"no IDevID recorded": {mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.devices.dev.IDevIDCert = ""
		}},
		"IDevID does not chain to the platform CA": {mutate: func(t *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.ca.bundle = newBootPKI(t).caPEM
		}},
		"IDevID not issued for client auth": {mutate: func(t *testing.T, f *bootFixture, in *BootDeliveryInput) {
			leaf, _, chain := f.pki.issue(t, "node-1.example", x509.ExtKeyUsageServerAuth)
			in.PeerLeaf, f.devices.dev.IDevIDCert = leaf, chain
		}},
		"revoked": {mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.devices.dev.State = entities.DeviceStateRevoked
		}},
		"suspended": {mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.devices.dev.State = entities.DeviceStateSuspended
		}},
		"quote made for another connection": {mutate: func(t *testing.T, _ *bootFixture, in *BootDeliveryInput) {
			in.Evidence = bootEvidence(t, []byte("a nonce from some other session"))
		}},
		"connection not bound": {mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) {
			in.ChannelNonce = nil
		}},
		"attestation did not verify": {reachVerifier: true, mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.attestor.resp.Verified = false
		}},
		"verifier answered for another device": {reachVerifier: true, mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.attestor.resp.DeviceId = bootDeviceID + 1
		}},
		"verifier refused to evaluate": {reachVerifier: true, mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
			f.attestor.resp, f.attestor.err = nil, status.Error(codes.FailedPrecondition, "no trustworthy attestation key")
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t)
			in := f.input(t)
			tc.mutate(t, f, &in)

			resp, err := f.service().Deliver(context.Background(), in)
			assert.Nil(t, resp)
			var refused ErrBootRefused
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, "SN-42", refused.Serial)
			if !tc.reachVerifier {
				assert.Empty(t, f.attestor.gotEvidence, "a node that is not the enrolled device must not reach the verifier")
			}
		})
	}
}

func TestBootService_Deliver_ClassifiesEveryOtherFailure(t *testing.T) {
	storage := errors.New("storage offline")
	cases := map[string]struct {
		mutate func(t *testing.T, f *bootFixture, in *BootDeliveryInput)
		target any
	}{
		"no evidence": {
			mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) { in.Evidence = nil },
			target: &ErrBootEvidenceRequired{},
		},
		"evidence not JSON": {
			mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) { in.Evidence = []byte("not json") },
			target: &ErrBootEvidenceUnreadable{},
		},
		"no identity": {
			mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) { in.Identity = "" },
			target: &ErrBootIdentityRequired{},
		},
		"unknown identity": {
			mutate: func(_ *testing.T, _ *bootFixture, in *BootDeliveryInput) { in.Identity = "stranger" },
			target: &ErrBootIdentityUnknown{},
		},
		"device lookup fails": {
			mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) { f.devices.err = storage },
			target: &ErrBootUnavailable{},
		},
		"CA bundle unavailable": {
			mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) { f.ca.err = storage },
			target: &ErrBootUnavailable{},
		},
		"verifier fault": {
			mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
				f.attestor.resp, f.attestor.err = nil, status.Error(codes.Internal, "store down")
			},
			target: &ErrBootUnavailable{},
		},
		"no profile bound": {
			mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
				f.profiles.profile, f.profiles.err = nil, device.ErrNoProfileForDevice{DeviceID: bootDeviceID}
			},
			target: &ErrBootProfileUnbound{},
		},
		"profile lookup fails": {
			mutate: func(_ *testing.T, f *bootFixture, _ *BootDeliveryInput) {
				f.profiles.profile, f.profiles.err = nil, storage
			},
			target: &ErrBootUnavailable{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t)
			in := f.input(t)
			tc.mutate(t, f, &in)

			resp, err := f.service().Deliver(context.Background(), in)
			assert.Nil(t, resp)
			require.ErrorAs(t, err, tc.target)
		})
	}
}

// certificateInput is the request a node makes for identity: a proof over
// the fixture's connection value, signed with key.
func (f *bootFixture) certificateInput(t *testing.T, identity string, key crypto.Signer) BootCertificateInput {
	t.Helper()
	signature, err := provisioning.SignBootCertificateProof(key, identity, f.nonce)
	require.NoError(t, err)
	return BootCertificateInput{Identity: identity, ChannelNonce: f.nonce, Signature: signature}
}

func TestBootService_Certificate_AnswersTheNodeHoldingTheKey(t *testing.T) {
	for _, identity := range []string{"node-1.example", "SN-42"} {
		t.Run(identity, func(t *testing.T) {
			f := newBootFixture(t)
			resp, err := f.service().Certificate(context.Background(), f.certificateInput(t, identity, f.pki.leafKey))
			require.NoError(t, err)
			assert.Equal(t, identity, resp.Identity)
			assert.Equal(t, f.pki.chainPEM, resp.IDevIDChain)
		})
	}
}

func TestBootService_Certificate_RefusesWithoutSayingWhy(t *testing.T) {
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cases := map[string]func(t *testing.T, f *bootFixture) BootCertificateInput{
		"unknown name": func(t *testing.T, f *bootFixture) BootCertificateInput {
			return f.certificateInput(t, "stranger", stranger)
		},
		"enrolled name, another key": func(t *testing.T, f *bootFixture) BootCertificateInput {
			return f.certificateInput(t, "node-1.example", stranger)
		},
		"IAK leads the recorded chain": func(t *testing.T, f *bootFixture) BootCertificateInput {
			// enroll-01's finalize PEM order (#764): the proof is checked
			// against the first certificate, which must be the IDevID.
			_, _, iakPEM := f.pki.issue(t, "IAK node-1.example", x509.ExtKeyUsageClientAuth)
			f.devices.dev.IDevIDCert = iakPEM + f.pki.chainPEM
			return f.certificateInput(t, "node-1.example", f.pki.leafKey)
		},
		"no chain recorded": func(t *testing.T, f *bootFixture) BootCertificateInput {
			f.devices.dev.IDevIDCert = ""
			return f.certificateInput(t, "node-1.example", f.pki.leafKey)
		},
		"proof made on another connection": func(t *testing.T, f *bootFixture) BootCertificateInput {
			in := f.certificateInput(t, "node-1.example", f.pki.leafKey)
			in.ChannelNonce = []byte("another-connection-exporter-32by")
			return in
		},
		"proof made for another name": func(t *testing.T, f *bootFixture) BootCertificateInput {
			in := f.certificateInput(t, "SN-42", f.pki.leafKey)
			in.Identity = "node-1.example"
			return in
		},
		"unbound connection": func(t *testing.T, f *bootFixture) BootCertificateInput {
			in := f.certificateInput(t, "node-1.example", f.pki.leafKey)
			in.ChannelNonce = nil
			return in
		},
		"no proof": func(t *testing.T, f *bootFixture) BootCertificateInput {
			return BootCertificateInput{Identity: "node-1.example", ChannelNonce: f.nonce}
		},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t)
			resp, err := f.service().Certificate(context.Background(), input(t, f))
			assert.Nil(t, resp)
			var refused ErrBootCertificateRefused
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, ErrBootCertificateRefused{}.Error(), err.Error(),
				"every refusal reads the same, so a name's enrollment cannot be learned")
		})
	}
}

func TestBootService_Certificate_Faults(t *testing.T) {
	f := newBootFixture(t)
	_, err := f.service().Certificate(context.Background(), BootCertificateInput{})
	assert.ErrorAs(t, err, &ErrBootIdentityRequired{})

	f.devices.err = errors.New("storage offline")
	_, err = f.service().Certificate(context.Background(), f.certificateInput(t, "node-1.example", f.pki.leafKey))
	assert.ErrorAs(t, err, &ErrBootUnavailable{})

	f = newBootFixture(t)
	f.devices.dev.IDevIDCert = "not a chain"
	_, err = f.service().Certificate(context.Background(), f.certificateInput(t, "node-1.example", f.pki.leafKey))
	assert.ErrorAs(t, err, &ErrBootUnavailable{})
}

func TestNewBootService_MissingDependencyYieldsNil(t *testing.T) {
	f := newBootFixture(t)
	assert.Nil(t, NewBootService(nil, f.profiles, f.attestor, f.ca))
	assert.Nil(t, NewBootService(f.devices, nil, f.attestor, f.ca))
	assert.Nil(t, NewBootService(f.devices, f.profiles, nil, f.ca))
	assert.Nil(t, NewBootService(f.devices, f.profiles, f.attestor, nil))
	assert.NotNil(t, f.service())
}

// TestBootErrors_MessagesAndCauses pins what each boot error tells the
// caller and that its cause stays reachable for the server's log. The
// certificate refusal is the exception: its message names neither the
// identity nor the cause, so the route cannot enumerate enrolled devices.
func TestBootErrors_MessagesAndCauses(t *testing.T) {
	cause := errors.New("underlying")
	cases := []struct {
		err  error
		want string
	}{
		{ErrBootIdentityRequired{}, "device: boot identity is required"},
		{ErrBootIdentityUnknown{Identity: "node-1", Cause: cause}, "device: no device is enrolled as node-1"},
		{ErrBootCertificateRequestUnreadable{Cause: cause}, "device: boot certificate request could not be read: underlying"},
		{ErrBootEvidenceRequired{}, "device: boot attestation evidence is required"},
		{ErrBootEvidenceUnreadable{Cause: cause}, "device: boot attestation evidence could not be read: underlying"},
		{ErrBootRefused{Serial: "SN1", Reason: "device is revoked"}, "device: boot delivery refused for SN1: device is revoked"},
		{ErrBootRefused{Serial: "SN1", Reason: "bad quote", Cause: cause}, "device: boot delivery refused for SN1: bad quote: underlying"},
		{ErrBootProfileUnbound{Serial: "SN1"}, "device: no profile is bound to SN1"},
		{ErrBootUnavailable{Reason: "no CA"}, "device: boot delivery unavailable: no CA"},
		{ErrBootUnavailable{Reason: "lookup", Cause: cause}, "device: boot delivery unavailable: lookup: underlying"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.err.Error())
	}

	for _, wrapped := range []error{
		ErrBootIdentityUnknown{Cause: cause},
		ErrBootCertificateRequestUnreadable{Cause: cause},
		ErrBootEvidenceUnreadable{Cause: cause},
		ErrBootRefused{Cause: cause},
		ErrBootUnavailable{Cause: cause},
		ErrBootCertificateRefused{Cause: cause},
	} {
		assert.ErrorIs(t, wrapped, cause, "%T keeps its cause", wrapped)
	}

	refused := ErrBootCertificateRefused{Identity: "node-1", Cause: cause}
	assert.Equal(t, "device: boot certificate refused", refused.Error())
	assert.NotContains(t, refused.Error(), "node-1")
	assert.NotContains(t, refused.Error(), "underlying")
}
