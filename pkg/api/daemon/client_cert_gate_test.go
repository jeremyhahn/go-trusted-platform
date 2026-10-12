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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// gateNodeName is the name the client leaf carries as its CN.
const gateNodeName = "node-1.example"

// gatePKI is a CA and the leaf certificates a listener and its clients use.
type gatePKI struct {
	pool   *x509.CertPool
	caPEM  []byte
	server tls.Certificate
	// client is the leaf of a diskless node enrolled as gateNodeName.
	client tls.Certificate
}

func newGatePKI(t *testing.T) gatePKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gate test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return gatePKI{
		pool:   pool,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		server: leaf(2, "gate test server", x509.ExtKeyUsageServerAuth),
		client: leaf(3, gateNodeName, x509.ExtKeyUsageClientAuth),
	}
}

// gateDeviceServer answers the two boot RPCs and one RPC that is not a boot
// RPC; the gate is what decides who may call which.
type gateDeviceServer struct {
	platformv1.UnimplementedDeviceServiceServer
}

func (gateDeviceServer) BootCertificate(context.Context, *platformv1.BootCertificateRequest) (*platformv1.BootCertificateResponse, error) {
	return &platformv1.BootCertificateResponse{}, nil
}

func (gateDeviceServer) BootDelivery(context.Context, *platformv1.BootDeliveryRequest) (*platformv1.BootDeliveryResponse, error) {
	return &platformv1.BootDeliveryResponse{}, nil
}

func (gateDeviceServer) ListDevices(context.Context, *platformv1.ListDevicesRequest) (*platformv1.ListDevicesResponse, error) {
	return &platformv1.ListDevicesResponse{}, nil
}

// serveGate starts one TLS gRPC listener configured as the daemon configures
// its own: a client certificate is verified if given, the gate decides the rest.
func serveGate(t *testing.T, pki gatePKI) string {
	t.Helper()
	return serveDeviceGated(t, pki, gateDeviceServer{})
}

// serveDeviceGated serves devices over a real TLS 1.3 gRPC listener behind
// the client-certificate gate, the way platformd mounts the device service.
func serveDeviceGated(t *testing.T, pki gatePKI, devices platformv1.DeviceServiceServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The daemon's own gRPC TCP transport security, so these tests break if
	// the listener goes back to requiring a client certificate at the
	// handshake.
	config := DefaultConfig()
	config.TLSCertificate = &pki.server
	config.EnableMTLS = true
	config.MTLSClientCAPool = pki.pool
	opts, err := grpcTCPServerTLS(config, logging.DefaultLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(opts...)
	platformv1.RegisterDeviceServiceServer(srv, devices)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		if err := <-served; err != nil {
			t.Errorf("serving the gated listener: %v", err)
		}
	})
	return lis.Addr().String()
}

func dialGate(t *testing.T, addr string, pki gatePKI, withCert bool) platformv1.DeviceServiceClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: pki.pool, MinVersion: tls.VersionTLS13}
	if withCert {
		cfg.Certificates = []tls.Certificate{pki.client}
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return platformv1.NewDeviceServiceClient(conn)
}

// TestClientCertGate_BootCallsOverOneListener runs both boot RPCs and a third
// over one TLS listener: BootCertificate needs no certificate, BootDelivery and
// every other method need a verified one.
func TestClientCertGate_BootCallsOverOneListener(t *testing.T) {
	pki := newGatePKI(t)
	addr := serveGate(t, pki)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	anon := dialGate(t, addr, pki, false)
	if _, err := anon.BootCertificate(ctx, &platformv1.BootCertificateRequest{}); err != nil {
		t.Errorf("BootCertificate without a client certificate: %v", err)
	}
	for name, call := range map[string]func() error{
		"BootDelivery": func() error { _, err := anon.BootDelivery(ctx, &platformv1.BootDeliveryRequest{}); return err },
		"ListDevices":  func() error { _, err := anon.ListDevices(ctx, &platformv1.ListDevicesRequest{}); return err },
	} {
		if got := status.Code(call()); got != codes.Unauthenticated {
			t.Errorf("%s without a client certificate = %v, want Unauthenticated", name, got)
		}
	}

	authed := dialGate(t, addr, pki, true)
	if _, err := authed.BootDelivery(ctx, &platformv1.BootDeliveryRequest{}); err != nil {
		t.Errorf("BootDelivery with a client certificate: %v", err)
	}
	if _, err := authed.ListDevices(ctx, &platformv1.ListDevicesRequest{}); err != nil {
		t.Errorf("ListDevices with a client certificate: %v", err)
	}
}

// TestClientCertGate_RefusesAnUnverifiedCertificate: a certificate from another
// CA fails the handshake, so VerifyClientCertIfGiven is not "accept anything".
func TestClientCertGate_RefusesAnUnverifiedCertificate(t *testing.T) {
	pki := newGatePKI(t)
	addr := serveGate(t, pki)
	other := newGatePKI(t)
	client := dialGate(t, addr, gatePKI{pool: pki.pool, client: other.client}, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.BootCertificate(ctx, &platformv1.BootCertificateRequest{}); err == nil {
		t.Error("a client certificate from an untrusted CA was accepted")
	}
}

func TestClientCertGate_NoPeerIsRefused(t *testing.T) {
	err := grpcClientCertGate(context.Background(), platformv1.DeviceService_ListDevices_FullMethodName)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("err = %v, want Unauthenticated", err)
	}
	if err := grpcClientCertGate(context.Background(), platformv1.DeviceService_BootCertificate_FullMethodName); err != nil {
		t.Errorf("BootCertificate with no peer: %v", err)
	}
}

func TestGRPCTCPServerTLS_RefusesWhatItCannotEnforce(t *testing.T) {
	pki := newGatePKI(t)
	logger := logging.DefaultLogger()

	config := DefaultConfig()
	if opts, err := grpcTCPServerTLS(config, logger); err != nil || len(opts) != 0 {
		t.Errorf("no TLS material = %d options, %v; want none", len(opts), err)
	}

	config.TLSCertificate = &pki.server
	config.EnableMTLS = true
	var required ErrTransportAuthRequired
	if _, err := grpcTCPServerTLS(config, logger); !errors.As(err, &required) {
		t.Errorf("mTLS with no client CA pool = %v, want ErrTransportAuthRequired", err)
	}

	config = DefaultConfig()
	config.GRPCTLSCertFile = t.TempDir() + "/missing.crt"
	config.GRPCTLSKeyFile = t.TempDir() + "/missing.key"
	var tlsFailed ErrTLSConfigFailed
	if _, err := grpcTCPServerTLS(config, logger); !errors.As(err, &tlsFailed) {
		t.Errorf("unloadable key pair = %v, want ErrTLSConfigFailed", err)
	}
}

func TestQUICServerMTLS_RefusesWhatItCannotEnforce(t *testing.T) {
	logger := logging.DefaultLogger()

	off := &tls.Config{}
	if err := quicServerMTLS(DefaultConfig(), off, nil, logger); err != nil || off.ClientAuth != tls.NoClientCert {
		t.Errorf("mTLS off = %v, ClientAuth %v; want no change", err, off.ClientAuth)
	}

	config := DefaultConfig()
	config.EnableMTLS = true
	var required ErrTransportAuthRequired
	if err := quicServerMTLS(config, nil, nil, logger); !errors.As(err, &required) {
		t.Errorf("mTLS with no TLS config = %v, want ErrTransportAuthRequired", err)
	}
	if err := quicServerMTLS(config, &tls.Config{}, nil, logger); !errors.As(err, &required) {
		t.Errorf("mTLS with no client CA pool = %v, want ErrTransportAuthRequired", err)
	}
}

func TestQUICClientCertRefusal(t *testing.T) {
	boot := func(sub byte) *quicwire.Request {
		return &quicwire.Request{Opcode: quicwire.OpProvisioningCategory, Payload: []byte{sub}}
	}
	verified := quic.WithConnectionTLS(context.Background(), &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}})
	unverified := quic.WithConnectionTLS(context.Background(), &tls.ConnectionState{})

	required := &QUICServiceHandler{}
	required.RequireClientCert()

	cases := map[string]struct {
		h       *QUICServiceHandler
		ctx     context.Context
		req     *quicwire.Request
		refused bool
	}{
		"boot certificate without a certificate": {required, unverified, boot(quicwire.DeviceSubBootCertificate), false},
		"boot delivery without a certificate":    {required, unverified, boot(quicwire.DeviceSubBootDelivery), true},
		"boot delivery with a certificate":       {required, verified, boot(quicwire.DeviceSubBootDelivery), false},
		"other opcode without a certificate":     {required, context.Background(), &quicwire.Request{Opcode: quicwire.OpTPM2Category}, true},
		"empty provisioning payload":             {required, unverified, &quicwire.Request{Opcode: quicwire.OpProvisioningCategory}, true},
		"gate not enabled":                       {&QUICServiceHandler{}, unverified, boot(quicwire.DeviceSubBootDelivery), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := tc.h.clientCertRefusal(tc.ctx, tc.req)
			if tc.refused != (resp != nil) {
				t.Fatalf("refusal = %v, want refused=%v", resp, tc.refused)
			}
			if resp != nil && resp.Status != quicwire.StatusUnauthorized {
				t.Errorf("status = %#x, want StatusUnauthorized", resp.Status)
			}
		})
	}
}

func TestErrClientCertRequiredNamesTheOperation(t *testing.T) {
	var err error = ErrClientCertRequired{Operation: "/x.Y/Z"}
	var target ErrClientCertRequired
	if !errors.As(err, &target) || err.Error() != "a verified client certificate is required for /x.Y/Z" {
		t.Errorf("err = %q", err)
	}
}
