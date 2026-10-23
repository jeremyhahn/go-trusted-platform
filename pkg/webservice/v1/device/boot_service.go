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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// BootIdentityResolver maps a node identity (serial or IDevID common name)
// to its device record. *device.Service satisfies it.
type BootIdentityResolver interface {
	ResolveIdentity(ctx context.Context, identity string) (*entities.Device, error)
}

// BootProfileFinder resolves the profile a registered device is bound to.
// *device.ProfileService satisfies it.
type BootProfileFinder interface {
	FindProfileForDevice(ctx context.Context, dev *entities.Device) (*entities.DeviceProfile, error)
}

// BootAttestor is the quote verifier every transport shares; the in-process
// DeviceService gRPC implementation satisfies it.
type BootAttestor interface {
	AttestDevice(ctx context.Context, req *platformv1.AttestDeviceRequest) (*platformv1.AttestDeviceResponse, error)
}

// BootCABundle is the platform CA's PEM bundle (roots and intermediates).
type BootCABundle interface {
	CABundle() ([]byte, error)
}

// BootDeliveryInput is what a diskless node's delivery request carries once
// the transport has been peeled off: who the mTLS layer says it is, the leaf
// it presented, the nonce derived from its connection, and its evidence.
type BootDeliveryInput struct {
	Identity     string
	PeerLeaf     *x509.Certificate
	ChannelNonce []byte
	Evidence     []byte
}

// BootDeliveryResponse is the server wire for POST /api/v1/device/boot,
// mirrored field for field by provisioning.BootDeliveryResponse. It is
// camelCase like the rest of the device-facing surface.
type BootDeliveryResponse struct {
	Serial      string `json:"serial"`
	IDevIDChain string `json:"idevidChain"`
	// AttestCert is the IAK certificate recorded at enrollment; empty when
	// none was recorded.
	AttestCert string          `json:"attestCert"`
	CABundle   string          `json:"caBundle"`
	Profile    ProfileResponse `json:"profile"`
	// PCRBaselineSource is "signed" or "tofu": what the quote was checked
	// against, so the node can log a trust-on-first-use acceptance.
	PCRBaselineSource   string `json:"pcrBaselineSource"`
	PCRBaselineCaptured bool   `json:"pcrBaselineCaptured"`
}

// BootService answers a diskless node's per-boot requests (#690). The node
// keeps nothing across a reboot but its TPM, so each boot it asks for the
// certificates and configuration it was enrolled with. It gets them only
// after presenting its recorded IDevID over mTLS and a quote that verifies
// against its profile's baseline, bound to that same connection.
type BootService struct {
	devices  BootIdentityResolver
	profiles BootProfileFinder
	attestor BootAttestor
	ca       BootCABundle
}

// NewBootService returns nil when any dependency is missing, so the routes
// are not registered rather than registered and failing.
func NewBootService(
	devices BootIdentityResolver,
	profiles BootProfileFinder,
	attestor BootAttestor,
	ca BootCABundle,
) *BootService {
	if devices == nil || profiles == nil || attestor == nil || ca == nil {
		return nil
	}
	return &BootService{devices: devices, profiles: profiles, attestor: attestor, ca: ca}
}

// BootCertificateInput is a boot-certificate request once the transport has
// been peeled off: the name the node claims, the nonce derived from its
// connection, and its signature over both.
type BootCertificateInput struct {
	Identity     string
	ChannelNonce []byte
	Signature    []byte
}

// BootChannel returns the channel nonce of the connection a boot request
// arrived on, or ErrBootChannelRequired naming the transport when it has
// none. Every transport calls it before the boot service, so an empty nonce
// never reaches Certificate or Deliver.
func BootChannel(state *tls.ConnectionState, transport string) ([]byte, error) {
	nonce, err := provisioning.BootChannelNonce(state)
	if err != nil {
		return nil, ErrBootChannelRequired{Transport: transport, Cause: err}
	}
	return nonce, nil
}

// Certificate returns the IDevID chain recorded for in.Identity to the node
// that proves it holds the chain's key: a signature over the identity and
// this connection's exporter value, checked against the recorded leaf. The
// request carries no client certificate, because the node needs this chain
// to present one. An unknown name, a device with no recorded chain and a
// proof that does not verify are one refusal, so the route cannot be used to
// learn which names are enrolled.
func (s *BootService) Certificate(ctx context.Context, in BootCertificateInput) (*provisioning.BootCertificateResponse, error) {
	dev, err := s.resolve(ctx, in.Identity)
	var unknown ErrBootIdentityUnknown
	if errors.As(err, &unknown) {
		return nil, ErrBootCertificateRefused{Identity: in.Identity, Cause: err}
	}
	if err != nil {
		return nil, err
	}
	if dev.IDevIDCert == "" {
		return nil, ErrBootCertificateRefused{Identity: in.Identity,
			Cause: &MessageError{Msg: "no IDevID chain was recorded at enrollment"}}
	}
	chain, err := provisioning.ParseCertificateChain([]byte(dev.IDevIDCert))
	if err != nil {
		return nil, ErrBootUnavailable{Reason: "recorded IDevID chain does not parse", Cause: err}
	}
	if err := provisioning.VerifyBootCertificateProof(chain[0].PublicKey, in.Identity, in.ChannelNonce, in.Signature); err != nil {
		return nil, ErrBootCertificateRefused{Identity: in.Identity, Cause: err}
	}
	return &provisioning.BootCertificateResponse{Identity: in.Identity, IDevIDChain: dev.IDevIDCert}, nil
}

// Deliver checks, in order, that the node is the device it claims to be and
// that its boot state verifies, and only then returns that device's
// material. Every check fails closed.
func (s *BootService) Deliver(ctx context.Context, in BootDeliveryInput) (*BootDeliveryResponse, error) {
	if len(in.Evidence) == 0 {
		return nil, ErrBootEvidenceRequired{}
	}
	dev, err := s.resolve(ctx, in.Identity)
	if err != nil {
		return nil, err
	}

	// A quarantined node may boot: quarantine is enforced on its network
	// port, and remediation needs the node up to re-attest. Revoked and
	// suspended nodes are refused their credentials outright.
	if dev.State == entities.DeviceStateRevoked || dev.State == entities.DeviceStateSuspended {
		return nil, ErrBootRefused{Serial: dev.Serial, Reason: "device is " + string(dev.State)}
	}

	bundlePEM, err := s.ca.CABundle()
	if err != nil {
		return nil, ErrBootUnavailable{Reason: "platform CA bundle unavailable", Cause: err}
	}
	if err := verifyRecordedIDevID(dev, in.PeerLeaf, bundlePEM); err != nil {
		return nil, err
	}

	if err := verifyChannelBinding(dev, in.Evidence, in.ChannelNonce); err != nil {
		return nil, err
	}
	verdict, err := s.attest(ctx, dev, in.Evidence)
	if err != nil {
		return nil, err
	}

	profile, err := s.profiles.FindProfileForDevice(ctx, dev)
	if err != nil {
		var unbound device.ErrNoProfileForDevice
		if errors.As(err, &unbound) {
			return nil, ErrBootProfileUnbound{Serial: dev.Serial}
		}
		return nil, ErrBootUnavailable{Reason: "profile lookup failed", Cause: err}
	}

	return &BootDeliveryResponse{
		Serial:              dev.Serial,
		IDevIDChain:         dev.IDevIDCert,
		AttestCert:          dev.AttestCert,
		CABundle:            string(bundlePEM),
		Profile:             *ProfileFromDeviceProfile(profile, dev.Serial),
		PCRBaselineSource:   verdict.GetPcrBaselineSource(),
		PCRBaselineCaptured: verdict.GetPcrBaselineCaptured(),
	}, nil
}

func (s *BootService) resolve(ctx context.Context, identity string) (*entities.Device, error) {
	if identity == "" {
		return nil, ErrBootIdentityRequired{}
	}
	dev, err := s.devices.ResolveIdentity(ctx, identity)
	if err != nil {
		var unknown *device.IdentityNotFoundError
		if errors.As(err, &unknown) {
			return nil, ErrBootIdentityUnknown{Identity: identity, Cause: err}
		}
		return nil, ErrBootUnavailable{Reason: "device lookup failed", Cause: err}
	}
	return dev, nil
}

// attest runs the shared verifier. A negative verdict and a call the
// verifier refused to evaluate (unusable evidence, no trustworthy AK) both
// refuse the boot; only a fault on the server's side is unavailable.
func (s *BootService) attest(ctx context.Context, dev *entities.Device, evidence []byte) (*platformv1.AttestDeviceResponse, error) {
	verdict, err := s.attestor.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId: strconv.FormatUint(dev.ID, 10),
		Evidence: evidence,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.PermissionDenied:
			return nil, ErrBootRefused{Serial: dev.Serial, Reason: "attestation could not be evaluated", Cause: err}
		default:
			return nil, ErrBootUnavailable{Reason: "attestation failed", Cause: err}
		}
	}
	if verdict.GetDeviceId() != dev.ID {
		return nil, ErrBootRefused{Serial: dev.Serial, Reason: "verifier answered for another device"}
	}
	if !verdict.GetVerified() {
		return nil, ErrBootRefused{Serial: dev.Serial, Reason: "attestation did not verify: " + verdict.GetMessage()}
	}
	return verdict, nil
}

// verifyRecordedIDevID requires the presented leaf to be exactly the IDevID
// recorded at enrollment, chaining to the platform CA for client auth. The
// mTLS layer already checked the chain; checking it here keeps the service
// correct whichever transport calls it.
func verifyRecordedIDevID(dev *entities.Device, presented *x509.Certificate, bundlePEM []byte) error {
	if presented == nil {
		return ErrBootRefused{Serial: dev.Serial, Reason: "no client certificate presented"}
	}
	if dev.IDevIDCert == "" {
		return ErrBootRefused{Serial: dev.Serial, Reason: "no IDevID was recorded at enrollment"}
	}
	chain, err := provisioning.ParseCertificateChain([]byte(dev.IDevIDCert))
	if err != nil {
		return ErrBootUnavailable{Reason: "recorded IDevID chain does not parse", Cause: err}
	}
	if !bytes.Equal(chain[0].Raw, presented.Raw) {
		return ErrBootRefused{Serial: dev.Serial, Reason: "presented certificate is not the recorded IDevID"}
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundlePEM) {
		return ErrBootUnavailable{Reason: "platform CA bundle holds no certificate"}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := presented.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return ErrBootRefused{Serial: dev.Serial, Reason: "IDevID does not chain to the platform CA", Cause: err}
	}
	return nil
}

// verifyChannelBinding requires the evidence's nonce to be this connection's
// exporter value. The verifier then proves the quote is over that nonce, so
// the quote was made for this connection and cannot be a replay.
func verifyChannelBinding(dev *entities.Device, evidence, channelNonce []byte) error {
	if len(channelNonce) == 0 {
		return ErrBootRefused{Serial: dev.Serial, Reason: "connection is not bound"}
	}
	var decoded vm.QuoteEvidence
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ErrBootEvidenceUnreadable{Cause: err}
	}
	if !bytes.Equal(decoded.Nonce, channelNonce) {
		return ErrBootRefused{Serial: dev.Serial, Reason: "quote nonce is not bound to this connection"}
	}
	return nil
}
