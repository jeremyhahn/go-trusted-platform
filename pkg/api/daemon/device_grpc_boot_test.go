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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bootNode is a TLS 1.3 connection between a diskless node (client, CN
// node-1.example) and the control plane (server), both ends' states.
type bootNode struct {
	cert        tls.Certificate
	leaf        *x509.Certificate
	key         *ecdsa.PrivateKey
	serverState tls.ConnectionState
	clientState tls.ConnectionState
}

func selfSigned(t *testing.T, cn string, eku x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, key
}

func newBootNode(t *testing.T) *bootNode {
	t.Helper()
	nodeCert, nodeLeaf, nodeKey := selfSigned(t, "node-1.example", x509.ExtKeyUsageClientAuth)
	serverCert, serverLeaf, _ := selfSigned(t, "control-plane.example", x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(serverLeaf)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	server := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	client := tls.Client(clientConn, &tls.Config{
		Certificates: []tls.Certificate{nodeCert},
		RootCAs:      roots,
		ServerName:   "control-plane.example",
		MinVersion:   tls.VersionTLS13,
	})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	require.NoError(t, client.Handshake())
	require.NoError(t, <-done)

	return &bootNode{
		cert:        nodeCert,
		leaf:        nodeLeaf,
		key:         nodeKey,
		serverState: server.ConnectionState(),
		clientState: client.ConnectionState(),
	}
}

// grpcCtx is the context a gRPC handler sees for this connection.
func (n *bootNode) grpcCtx() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: n.serverState},
	})
}

// stubBoot records what the transport handed the boot service.
type stubBoot struct {
	certIn    restdevice.BootCertificateInput
	deliverIn restdevice.BootDeliveryInput
	certResp  *provisioning.BootCertificateResponse
	delResp   *restdevice.BootDeliveryResponse
	err       error
}

func (s *stubBoot) Certificate(_ context.Context, in restdevice.BootCertificateInput) (*provisioning.BootCertificateResponse, error) {
	s.certIn = in
	return s.certResp, s.err
}

func (s *stubBoot) Deliver(_ context.Context, in restdevice.BootDeliveryInput) (*restdevice.BootDeliveryResponse, error) {
	s.deliverIn = in
	return s.delResp, s.err
}

func newBootGRPC(boot BootProvider) *DeviceGRPCService {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	svc.boot = boot
	return svc
}

func TestDeviceGRPC_BootCertificate_BindsTheRequestToItsConnection(t *testing.T) {
	node := newBootNode(t)
	stub := &stubBoot{certResp: &provisioning.BootCertificateResponse{Identity: "node-1.example", IDevIDChain: "chain-pem"}}

	resp, err := newBootGRPC(stub).BootCertificate(node.grpcCtx(), &platformv1.BootCertificateRequest{
		Identity:  "node-1.example",
		Signature: []byte("sig"),
	})
	require.NoError(t, err)

	nodeNonce, err := provisioning.BootChannelNonce(&node.clientState)
	require.NoError(t, err)
	assert.Equal(t, nodeNonce, stub.certIn.ChannelNonce, "the server derives the same nonce the node signed")
	assert.Equal(t, "node-1.example", stub.certIn.Identity)
	assert.Equal(t, []byte("sig"), stub.certIn.Signature)
	assert.Equal(t, "chain-pem", resp.GetIdevidChain())
	assert.Equal(t, "node-1.example", resp.GetIdentity())
}

// A connection with no channel binding is refused with a typed
// FailedPrecondition naming its transport, and the boot service is never
// reached: an empty nonce must not stand in for a binding.
func TestDeviceGRPC_Boot_RefusedWithoutAChannel(t *testing.T) {
	unixPeer := &peer.Peer{Addr: &net.UnixAddr{Name: "/run/platformd.sock", Net: "unix"}}
	tls12 := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{Version: tls.VersionTLS12}}}
	cases := map[string]struct {
		ctx       context.Context
		transport string
	}{
		"no peer":              {context.Background(), "gRPC"},
		"Unix socket":          {peer.NewContext(context.Background(), unixPeer), "Unix"},
		"TLS 1.2 has no value": {peer.NewContext(context.Background(), tls12), "gRPC"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &stubBoot{}
			svc := newBootGRPC(stub)

			_, err := svc.BootCertificate(tc.ctx, &platformv1.BootCertificateRequest{Identity: "x", Signature: []byte("sig")})
			assertChannelRefusal(t, err, tc.transport)
			_, err = svc.BootDelivery(tc.ctx, &platformv1.BootDeliveryRequest{Evidence: []byte("e")})
			assertChannelRefusal(t, err, tc.transport)

			assert.Equal(t, restdevice.BootCertificateInput{}, stub.certIn, "the boot service was not called")
			assert.Equal(t, restdevice.BootDeliveryInput{}, stub.deliverIn, "the boot service was not called")
		})
	}
}

func assertChannelRefusal(t *testing.T, err error, transport string) {
	t.Helper()
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "this "+transport+" request has none")
}

func TestDeviceGRPC_BootCertificate_QUICConnectionTLSIsUsed(t *testing.T) {
	node := newBootNode(t)
	stub := &stubBoot{certResp: &provisioning.BootCertificateResponse{}}
	ctx := apiquic.WithConnectionTLS(context.Background(), &node.serverState)

	_, err := newBootGRPC(stub).BootCertificate(ctx, &platformv1.BootCertificateRequest{Identity: "node-1.example"})
	require.NoError(t, err)

	want, err := provisioning.BootChannelNonce(&node.serverState)
	require.NoError(t, err)
	assert.Equal(t, want, stub.certIn.ChannelNonce)
}

func TestDeviceGRPC_BootDelivery_IdentityIsTheClientCertificates(t *testing.T) {
	node := newBootNode(t)
	stub := &stubBoot{delResp: &restdevice.BootDeliveryResponse{
		Serial:      "SN-42",
		IDevIDChain: "chain",
		AttestCert:  "iak",
		CABundle:    "ca",
		Profile: restdevice.ProfileResponse{
			SerialNumber:        "SN-42",
			AdmittedNetwork:     restdevice.NetworkConfig{VLAN: 20, StaticIP: "10.0.0.2/24", Gateway: "10.0.0.1", DNS: []string{"10.0.0.1"}},
			ProvisioningNetwork: &restdevice.NetworkConfig{VLAN: 10, UseDHCP: true},
			ACLs:                []restdevice.ACLConfig{{Name: "acl-0", Priority: 5, Match: map[string]string{"protocol": "tcp"}, Action: "allow"}},
			RateLimit:           &restdevice.RateLimitConfig{IngressMbps: 100, EgressMbps: 50},
		},
		PCRBaselineSource:   "tofu",
		PCRBaselineCaptured: true,
	}}

	resp, err := newBootGRPC(stub).BootDelivery(node.grpcCtx(), &platformv1.BootDeliveryRequest{Evidence: []byte("evidence")})
	require.NoError(t, err)

	assert.Equal(t, "node-1.example", stub.deliverIn.Identity, "the identity comes from the certificate, not the request")
	assert.True(t, node.leaf.Equal(stub.deliverIn.PeerLeaf))
	assert.Equal(t, []byte("evidence"), stub.deliverIn.Evidence)
	want, err := provisioning.BootChannelNonce(&node.clientState)
	require.NoError(t, err)
	assert.Equal(t, want, stub.deliverIn.ChannelNonce)

	assert.Equal(t, "SN-42", resp.GetSerial())
	assert.Equal(t, "iak", resp.GetAttestCert())
	assert.Equal(t, "ca", resp.GetCaBundle())
	assert.Equal(t, "tofu", resp.GetPcrBaselineSource())
	assert.True(t, resp.GetPcrBaselineCaptured())
	profile := resp.GetProfile()
	assert.Equal(t, uint32(20), profile.GetAdmittedNetwork().GetVlan())
	assert.Equal(t, "10.0.0.2/24", profile.GetAdmittedNetwork().GetStaticIp())
	assert.True(t, profile.GetProvisioningNetwork().GetUseDhcp())
	require.Len(t, profile.GetAcls(), 1)
	assert.Equal(t, "tcp", profile.GetAcls()[0].GetMatch()["protocol"])
	assert.Equal(t, int32(100), profile.GetRateLimit().GetIngressMbps())
}

func TestDeviceGRPC_BootDelivery_WithoutAClientCertificateSendsNoIdentity(t *testing.T) {
	node := newBootNode(t)
	anonymous := node.serverState
	anonymous.PeerCertificates = nil
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: anonymous}})
	stub := &stubBoot{err: restdevice.ErrBootIdentityRequired{}}

	_, err := newBootGRPC(stub).BootDelivery(ctx, &platformv1.BootDeliveryRequest{Evidence: []byte("e")})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, stub.deliverIn.Identity)
	assert.Nil(t, stub.deliverIn.PeerLeaf)
	assert.NotEmpty(t, stub.deliverIn.ChannelNonce, "the connection is still bound")
}

func TestDeviceGRPC_Boot_UnavailableWithoutAService(t *testing.T) {
	svc := newBootGRPC(nil)

	_, err := svc.BootCertificate(context.Background(), &platformv1.BootCertificateRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = svc.BootDelivery(context.Background(), &platformv1.BootDeliveryRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestDeviceGRPC_Boot_ErrorMapping(t *testing.T) {
	node := newBootNode(t)
	cases := map[string]struct {
		err  error
		code codes.Code
	}{
		"identity required":   {restdevice.ErrBootIdentityRequired{}, codes.InvalidArgument},
		"evidence required":   {restdevice.ErrBootEvidenceRequired{}, codes.InvalidArgument},
		"evidence unreadable": {restdevice.ErrBootEvidenceUnreadable{Cause: errors.New("bad")}, codes.InvalidArgument},
		"certificate refused": {restdevice.ErrBootCertificateRefused{Identity: "x", Cause: errors.New("bad")}, codes.PermissionDenied},
		"delivery refused":    {restdevice.ErrBootRefused{Serial: "SN", Reason: "revoked"}, codes.PermissionDenied},
		"unknown identity":    {restdevice.ErrBootIdentityUnknown{Identity: "x"}, codes.NotFound},
		"profile unbound":     {restdevice.ErrBootProfileUnbound{Serial: "SN"}, codes.NotFound},
		"dependency down":     {restdevice.ErrBootUnavailable{Reason: "lookup", Cause: errors.New("db")}, codes.Unavailable},
		"anything else":       {errors.New("boom"), codes.Internal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := newBootGRPC(&stubBoot{err: tc.err})

			_, err := svc.BootCertificate(node.grpcCtx(), &platformv1.BootCertificateRequest{})
			assert.Equal(t, tc.code, status.Code(err))
			_, err = svc.BootDelivery(node.grpcCtx(), &platformv1.BootDeliveryRequest{})
			assert.Equal(t, tc.code, status.Code(err))
		})
	}
}

// bootDevices answers one enrolled device whatever the lookup.
type bootDevices struct{ dev *entities.Device }

func (b bootDevices) ResolveIdentity(_ context.Context, identity string) (*entities.Device, error) {
	if identity != b.dev.Hostname {
		return nil, &device.IdentityNotFoundError{Identity: identity}
	}
	copied := *b.dev
	return &copied, nil
}

type bootCA struct{ pem []byte }

func (b bootCA) CABundle() ([]byte, error) { return b.pem, nil }

// TestDeviceGRPC_BootCertificate_EnforcesProofOfPossession runs the real boot
// service behind the gRPC method: the chain is returned only to the holder of
// the recorded IDevID key, signing this connection's exporter value.
func TestDeviceGRPC_BootCertificate_EnforcesProofOfPossession(t *testing.T) {
	node := newBootNode(t)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.leaf.Raw}))
	boot := restdevice.NewBootService(
		bootDevices{dev: &entities.Device{ID: 42, Serial: "SN-42", Hostname: "node-1.example", IDevIDCert: chain}},
		bootFinder{},
		stubAttestor{},
		bootCA{},
	)
	require.NotNil(t, boot)
	svc := newBootGRPC(boot)

	nonce, err := provisioning.BootChannelNonce(&node.clientState)
	require.NoError(t, err)
	proof, err := provisioning.SignBootCertificateProof(node.key, "node-1.example", nonce)
	require.NoError(t, err)

	resp, err := svc.BootCertificate(node.grpcCtx(), &platformv1.BootCertificateRequest{Identity: "node-1.example", Signature: proof})
	require.NoError(t, err)
	assert.Equal(t, chain, resp.GetIdevidChain())

	t.Run("a signature over another connection is refused", func(t *testing.T) {
		other, err := provisioning.SignBootCertificateProof(node.key, "node-1.example", []byte("another connection's value....32"))
		require.NoError(t, err)
		_, err = svc.BootCertificate(node.grpcCtx(), &platformv1.BootCertificateRequest{Identity: "node-1.example", Signature: other})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("a connection with no TLS is refused", func(t *testing.T) {
		_, err := svc.BootCertificate(context.Background(), &platformv1.BootCertificateRequest{Identity: "node-1.example", Signature: proof})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("an unknown name is refused like a bad proof", func(t *testing.T) {
		_, err := svc.BootCertificate(node.grpcCtx(), &platformv1.BootCertificateRequest{Identity: "nobody", Signature: proof})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

type bootFinder struct{}

func (bootFinder) FindProfileForDevice(context.Context, *entities.Device) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

type stubAttestor struct{}

func (stubAttestor) AttestDevice(context.Context, *platformv1.AttestDeviceRequest) (*platformv1.AttestDeviceResponse, error) {
	return &platformv1.AttestDeviceResponse{Verified: true}, nil
}

func TestNewDeviceBootProvider_NeedsEveryDependency(t *testing.T) {
	assert.Nil(t, newDeviceBootProvider(&DeviceGRPCService{}), "no CA, no provider")
	assert.Nil(t, newDeviceBootProvider(&DeviceGRPCService{bootCA: bootCA{}}),
		"a device service that cannot resolve identities yields no provider")
}
