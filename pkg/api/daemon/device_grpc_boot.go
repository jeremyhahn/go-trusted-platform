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

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// BootCABundle is the platform CA bundle source for diskless boot delivery.
type BootCABundle = restdevice.BootCABundle

// BootProvider is the diskless-boot operation behind
// DeviceService.BootCertificate and DeviceService.BootDelivery on every
// transport. The single implementation is *restdevice.BootService, which
// holds the proof-of-possession, channel-binding and attestation checks; the
// transports only peel their framing off and map the outcome.
type BootProvider interface {
	Certificate(ctx context.Context, in restdevice.BootCertificateInput) (*provisioning.BootCertificateResponse, error)
	Deliver(ctx context.Context, in restdevice.BootDeliveryInput) (*restdevice.BootDeliveryResponse, error)
}

// WithDeviceBootCA supplies the platform CA bundle source. Without it the
// boot RPCs answer Unavailable: a node cannot be handed a CA it cannot name.
func WithDeviceBootCA(ca BootCABundle) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.bootCA = ca }
}

// newDeviceBootProvider builds the shared boot service over this gRPC
// service, which is its own quote verifier. The device and profile services
// must also resolve identities and find a device's profile (*device.Service
// and *device.ProfileService do). It returns nil (an untyped nil interface)
// when any dependency is missing.
func newDeviceBootProvider(s *DeviceGRPCService) BootProvider {
	if s.bootCA == nil {
		return nil
	}
	devices, ok := s.deviceService.(restdevice.BootIdentityResolver)
	if !ok {
		return nil
	}
	profiles, ok := s.profileService.(restdevice.BootProfileFinder)
	if !ok {
		return nil
	}
	boot := restdevice.NewBootService(devices, profiles, s, s.bootCA)
	if boot == nil {
		return nil
	}
	return boot
}

// Transport names used in ErrBootChannelRequired.
const (
	bootTransportGRPC = "gRPC"
	bootTransportUnix = "Unix"
	bootTransportQUIC = "QUIC"
	bootTransportMCP  = "MCP"
)

// connectionTLS returns the TLS state of the connection a request arrived
// on and the transport it arrived over: the QUIC server's state, when it put
// one in the context, else the gRPC peer's. The state is nil for a transport
// with no TLS (the Unix socket), which bootChannel refuses.
func connectionTLS(ctx context.Context) (*tls.ConnectionState, string) {
	if state := apiquic.ConnectionTLS(ctx); state != nil {
		return state, bootTransportQUIC
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, bootTransportGRPC
	}
	transport := bootTransportGRPC
	if p.Addr != nil && p.Addr.Network() == "unix" {
		transport = bootTransportUnix
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, transport
	}
	return &info.State, transport
}

// BootCertificate returns the IDevID chain recorded for the claimed identity
// to the node that proves it holds the chain's key over this connection.
func (s *DeviceGRPCService) BootCertificate(
	ctx context.Context,
	req *platformv1.BootCertificateRequest,
) (*platformv1.BootCertificateResponse, error) {
	if s.boot == nil {
		return nil, status.Error(codes.Unavailable, "diskless boot is not available")
	}
	nonce, err := restdevice.BootChannel(connectionTLS(ctx))
	if err != nil {
		return nil, s.bootErrorToGRPC(err)
	}
	resp, err := s.boot.Certificate(ctx, restdevice.BootCertificateInput{
		Identity:     req.GetIdentity(),
		ChannelNonce: nonce,
		Signature:    req.GetSignature(),
	})
	if err != nil {
		return nil, s.bootErrorToGRPC(err)
	}
	return &platformv1.BootCertificateResponse{
		Identity:    resp.Identity,
		IdevidChain: resp.IDevIDChain,
	}, nil
}

// BootDelivery returns a verified node's profile and CA bundle. The identity
// is the client certificate's, never a request field.
func (s *DeviceGRPCService) BootDelivery(
	ctx context.Context,
	req *platformv1.BootDeliveryRequest,
) (*platformv1.BootDeliveryResponse, error) {
	if s.boot == nil {
		return nil, status.Error(codes.Unavailable, "diskless boot is not available")
	}
	state, transport := connectionTLS(ctx)
	nonce, err := restdevice.BootChannel(state, transport)
	if err != nil {
		return nil, s.bootErrorToGRPC(err)
	}
	var (
		leaf     *x509.Certificate
		identity string
	)
	if len(state.PeerCertificates) > 0 {
		leaf = state.PeerCertificates[0]
		identity = middleware.DeviceSerialFromCert(leaf)
	}
	resp, err := s.boot.Deliver(ctx, restdevice.BootDeliveryInput{
		Identity:     identity,
		PeerLeaf:     leaf,
		ChannelNonce: nonce,
		Evidence:     req.GetEvidence(),
	})
	if err != nil {
		return nil, s.bootErrorToGRPC(err)
	}
	s.logger.Info("diskless boot delivery served",
		"serial", resp.Serial,
		"pcrBaselineSource", resp.PCRBaselineSource)
	return bootDeliveryToProto(resp), nil
}

// bootErrorToGRPC maps the boot service's typed errors onto gRPC codes, the
// same classification the REST handler applies to HTTP statuses.
func (s *DeviceGRPCService) bootErrorToGRPC(err error) error {
	var (
		identityRequired restdevice.ErrBootIdentityRequired
		evidenceRequired restdevice.ErrBootEvidenceRequired
		unreadable       restdevice.ErrBootEvidenceUnreadable
		unknown          restdevice.ErrBootIdentityUnknown
		unbound          restdevice.ErrBootProfileUnbound
		refused          restdevice.ErrBootRefused
		certRefused      restdevice.ErrBootCertificateRefused
		unavailable      restdevice.ErrBootUnavailable
		channel          restdevice.ErrBootChannelRequired
	)
	switch {
	case errors.As(err, &identityRequired), errors.As(err, &evidenceRequired), errors.As(err, &unreadable):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &channel):
		s.logger.Warn("diskless boot connection cannot be bound", "transport", channel.Transport, "reason", channel.Cause)
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &certRefused):
		s.logger.Warn("diskless boot certificate refused", "identity", certRefused.Identity, "reason", certRefused.Cause)
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &unknown), errors.As(err, &unbound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &refused):
		s.logger.Warn("diskless boot delivery refused", "serial", refused.Serial, "reason", refused.Reason)
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &unavailable):
		s.logger.Error("diskless boot request failed", "error", err)
		return status.Error(codes.Unavailable, err.Error())
	default:
		s.logger.Error("diskless boot request failed", "error", err)
		return status.Error(codes.Internal, err.Error())
	}
}

func bootDeliveryToProto(resp *restdevice.BootDeliveryResponse) *platformv1.BootDeliveryResponse {
	profile := &platformv1.BootProfile{
		SerialNumber:        resp.Profile.SerialNumber,
		AdmittedNetwork:     bootNetworkToProto(&resp.Profile.AdmittedNetwork),
		ProvisioningNetwork: bootNetworkToProto(resp.Profile.ProvisioningNetwork),
	}
	for _, acl := range resp.Profile.ACLs {
		profile.Acls = append(profile.Acls, &platformv1.BootACL{
			Name:     acl.Name,
			Priority: int32(acl.Priority),
			Match:    acl.Match,
			Action:   acl.Action,
		})
	}
	if rl := resp.Profile.RateLimit; rl != nil {
		profile.RateLimit = &platformv1.BootRateLimit{
			IngressMbps: int32(rl.IngressMbps),
			EgressMbps:  int32(rl.EgressMbps),
		}
	}
	return &platformv1.BootDeliveryResponse{
		Serial:              resp.Serial,
		IdevidChain:         resp.IDevIDChain,
		AttestCert:          resp.AttestCert,
		CaBundle:            resp.CABundle,
		Profile:             profile,
		PcrBaselineSource:   resp.PCRBaselineSource,
		PcrBaselineCaptured: resp.PCRBaselineCaptured,
	}
}

func bootNetworkToProto(n *restdevice.NetworkConfig) *platformv1.BootNetworkConfig {
	if n == nil {
		return nil
	}
	return &platformv1.BootNetworkConfig{
		Vlan:     uint32(n.VLAN),
		UseDhcp:  n.UseDHCP,
		StaticIp: n.StaticIP,
		Gateway:  n.Gateway,
		Dns:      n.DNS,
	}
}

// errBootOverMCP is the answer to both diskless boot tools on MCP. The
// daemon serves MCP over plain HTTP and stdio, so a boot request there has
// no TLS connection for its proof to be bound to; both MCP service providers
// refuse it here, before the boot service.
func errBootOverMCP() error {
	return restdevice.ErrBootChannelRequired{
		Transport: bootTransportMCP,
		Cause:     &provisioning.ErrBootChannelUnbound{Reason: "MCP is served over plain HTTP or stdio"},
	}
}
