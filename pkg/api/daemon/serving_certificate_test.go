package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLoopbackServingCert returns a self-signed certificate for 127.0.0.1
// with the given serial, so a client trusting it directly can tell which of
// two certificates a listener presented.
func newLoopbackServingCert(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "platformd.localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// presentedSerial completes a TLS 1.3 handshake with addr, trusting roots,
// and returns the serial of the leaf the server presented. Dialing an IP
// sends no SNI, the case where crypto/tls would otherwise prefer
// Certificates[0] over GetCertificate. It offers h2 because the gRPC server
// refuses a handshake that negotiates no ALPN protocol.
func presentedSerial(t *testing.T, addr string, roots *x509.CertPool) *big.Int {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	})
	require.NoError(t, err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber
}

func TestDaemon_MCPHTTPPresentsRenewedTLSIdentity(t *testing.T) {
	first := newLoopbackServingCert(t, 1)
	renewed := newLoopbackServingCert(t, 2)
	roots := x509.NewCertPool()
	roots.AddCert(first.Leaf)
	roots.AddCert(renewed.Leaf)

	serving, err := NewServingCertificate(first)
	require.NoError(t, err)
	config := mcpOnlyConfig(reservePort(t))
	config.TLSIdentity = serving

	d, err := New(config)
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, d.Stop(ctx))
	}()

	addr := config.MCPConfig.HTTPAddr
	assert.Equal(t, int64(1), presentedSerial(t, addr, roots).Int64())

	require.NoError(t, serving.Store(renewed))
	assert.Equal(t, int64(2), presentedSerial(t, addr, roots).Int64(),
		"the next handshake presents the renewed certificate without a restart")
}

// TestDaemon_GRPCTCPPresentsRenewedTLSIdentity proves the gRPC TCP listener
// of a running daemon presents a renewed TLSIdentity on the next handshake
// (#36): its credentials read the identity per handshake instead of pinning
// the certificate it started with.
func TestDaemon_GRPCTCPPresentsRenewedTLSIdentity(t *testing.T) {
	first := newLoopbackServingCert(t, 1)
	renewed := newLoopbackServingCert(t, 2)
	roots := x509.NewCertPool()
	roots.AddCert(first.Leaf)
	roots.AddCert(renewed.Leaf)

	serving, err := NewServingCertificate(first)
	require.NoError(t, err)
	config := testConfig(filepath.Join(t.TempDir(), "platformd.sock"))
	config.EnableREST = false
	config.EnableGRPCTCP = true
	config.GRPCListenAddr = "127.0.0.1:0"
	config.TLSCertificate = nil
	config.TLSIdentity = serving

	d, err := New(config)
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, d.Stop(ctx))
	}()

	addr := d.grpcListener.Addr().String()
	assert.Equal(t, int64(1), presentedSerial(t, addr, roots).Int64())

	require.NoError(t, serving.Store(renewed))
	assert.Equal(t, int64(2), presentedSerial(t, addr, roots).Int64(),
		"the next gRPC handshake presents the renewed certificate without a restart")
}

func TestNewServerTLSConfig_TLSIdentityReadsPerHandshake(t *testing.T) {
	first := newLoopbackServingCert(t, 1)
	serving, err := NewServingCertificate(first)
	require.NoError(t, err)
	config := DefaultConfig()
	config.TLSIdentity = serving

	tlsConfig, err := newServerTLSConfig(config, transportREST, first)
	require.NoError(t, err)
	assert.Empty(t, tlsConfig.Certificates, "a static entry would win over GetCertificate without SNI")
	require.NotNil(t, tlsConfig.GetCertificate)

	renewed := newLoopbackServingCert(t, 2)
	require.NoError(t, serving.Store(renewed))
	got, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Leaf.SerialNumber.Int64())
}

func TestNewServerTLSConfig_WithoutTLSIdentityServesStaticCert(t *testing.T) {
	cert := newLoopbackServingCert(t, 1)
	tlsConfig, err := newServerTLSConfig(DefaultConfig(), transportREST, cert)
	require.NoError(t, err)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.Nil(t, tlsConfig.GetCertificate)
}

func TestServingCertificate_StoreRefusesUnusableAndKeepsCurrent(t *testing.T) {
	current := newLoopbackServingCert(t, 1)
	serving, err := NewServingCertificate(current)
	require.NoError(t, err)

	noKey := newLoopbackServingCert(t, 2)
	noKey.PrivateKey = nil
	for name, bad := range map[string]tls.Certificate{
		"empty":    {},
		"no key":   noKey,
		"no chain": {PrivateKey: current.PrivateKey},
	} {
		err := serving.Store(bad)
		var want ErrUnusableServingCertificate
		assert.True(t, errors.As(err, &want), "%s: err = %v", name, err)
		assert.Equal(t, int64(1), serving.Current().Leaf.SerialNumber.Int64(), "%s: current replaced", name)
	}
}

func TestNewServingCertificate_RejectsUnusable(t *testing.T) {
	serving, err := NewServingCertificate(tls.Certificate{})
	var want ErrUnusableServingCertificate
	require.True(t, errors.As(err, &want), "err = %v", err)
	assert.Nil(t, serving)
}

func TestServingCertificate_GetCertificateWithoutCertFails(t *testing.T) {
	var empty ServingCertificate
	cert, err := empty.GetCertificate(&tls.ClientHelloInfo{})
	var want ErrNoServingCertificate
	require.True(t, errors.As(err, &want), "err = %v", err)
	assert.Nil(t, cert)

	var nilServing *ServingCertificate
	assert.Nil(t, nilServing.Current())
}

func TestConfig_InMemoryCertificatePrefersTLSIdentity(t *testing.T) {
	static := newLoopbackServingCert(t, 1)
	config := DefaultConfig()
	config.TLSCertificate = &static
	assert.Same(t, &static, config.inMemoryCertificate())

	serving, err := NewServingCertificate(newLoopbackServingCert(t, 2))
	require.NoError(t, err)
	config.TLSIdentity = serving
	assert.Equal(t, int64(2), config.inMemoryCertificate().Leaf.SerialNumber.Int64())
	assert.True(t, config.grpcTLSMaterialPresent())
}
