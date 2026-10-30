package quicbaaskms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFakeBackend is the failure the fake SDK clients below return when a
// test asks them to fail.
var errFakeBackend = errors.New("fake backend failure")

// fakeHealth implements quicbaas.HealthClient for the two calls the adapter
// makes. The embedded interface is nil: any other call panics, which flags an
// adapter change that reaches further into the SDK than these tests expect.
type fakeHealth struct {
	quicbaas.HealthClient
	err error
}

func (f *fakeHealth) Readiness(context.Context) (*quicbaas.HealthResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.HealthResponse{}, nil
}

func (f *fakeHealth) Ping(context.Context) error {
	return f.err
}

// fakeKMS implements the quicbaas.KMSClient calls the adapter makes.
type fakeKMS struct {
	quicbaas.KMSClient
	err error
}

func (f *fakeKMS) GenerateKey(_ context.Context, req *quicbaas.GenerateKeyRequest) (*quicbaas.GenerateKeyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.GenerateKeyResponse{}, nil
}

func (f *fakeKMS) GetKey(context.Context, string) (*quicbaas.KeyInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.KeyInfo{}, nil
}

func (f *fakeKMS) ListKeys(context.Context) (*quicbaas.ListKeysResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.ListKeysResponse{}, nil
}

func (f *fakeKMS) RotateKey(context.Context, string) (*quicbaas.RotateKeyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.RotateKeyResponse{}, nil
}

func (f *fakeKMS) DeleteKey(context.Context, string) error {
	return f.err
}

// fakeCrypto implements the quicbaas.CryptoClient calls the adapter makes.
type fakeCrypto struct {
	quicbaas.CryptoClient
	err error
}

func (f *fakeCrypto) Sign(context.Context, *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.SignResponse{}, nil
}

func (f *fakeCrypto) Verify(context.Context, *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.VerifyResponse{}, nil
}

func (f *fakeCrypto) Encrypt(context.Context, *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.EncryptResponse{}, nil
}

func (f *fakeCrypto) Decrypt(context.Context, *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaas.DecryptResponse{}, nil
}

// fakeSecurity returns the configured KMS and Crypto clients; a nil field is
// returned as an untyped nil interface so the adapter's nil checks see it.
type fakeSecurity struct {
	quicbaas.SecurityService
	kms    *fakeKMS
	crypto *fakeCrypto
}

func (f *fakeSecurity) KMS() quicbaas.KMSClient {
	if f.kms == nil {
		return nil
	}
	return f.kms
}

func (f *fakeSecurity) Crypto() quicbaas.CryptoClient {
	if f.crypto == nil {
		return nil
	}
	return f.crypto
}

// fakeClient implements the quicbaas.Client calls the adapter makes and
// records whether Close was called.
type fakeClient struct {
	quicbaas.Client
	security *fakeSecurity
	health   *fakeHealth
	closeErr error
	closed   bool
}

func (f *fakeClient) Security() quicbaas.SecurityService {
	return f.security
}

func (f *fakeClient) Health() quicbaas.HealthClient {
	if f.health == nil {
		return nil
	}
	return f.health
}

func (f *fakeClient) Close() error {
	f.closed = true
	return f.closeErr
}

// newFakeClient returns a client whose sub-clients all fail with err (or
// succeed when err is nil).
func newFakeClient(err error) *fakeClient {
	return &fakeClient{
		security: &fakeSecurity{kms: &fakeKMS{err: err}, crypto: &fakeCrypto{err: err}},
		health:   &fakeHealth{err: err},
	}
}

// startedAdapter returns an embedded-config adapter already holding client,
// as Start leaves it after a successful createClient.
func startedAdapter(t *testing.T, client quicbaas.Client) *Adapter {
	t.Helper()
	adapter, err := NewAdapter(DefaultConfig(), logging.NewLogger(slog.LevelDebug, nil))
	require.NoError(t, err)
	adapter.client = client
	adapter.started.Store(true)
	return adapter
}

func TestCoverage964_OperationsDelegateToSDK(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	adapter := startedAdapter(t, newFakeClient(nil))

	health, err := adapter.Health(ctx)
	require.NoError(t, err)
	assert.NotNil(t, health)
	require.NoError(t, adapter.Ping(ctx))

	generated, err := adapter.GenerateKey(ctx, &quicbaas.GenerateKeyRequest{Name: "k"})
	require.NoError(t, err)
	assert.NotNil(t, generated)
	info, err := adapter.GetKey(ctx, "k")
	require.NoError(t, err)
	assert.NotNil(t, info)
	listed, err := adapter.ListKeys(ctx)
	require.NoError(t, err)
	assert.NotNil(t, listed)
	rotated, err := adapter.RotateKey(ctx, "k")
	require.NoError(t, err)
	assert.NotNil(t, rotated)
	require.NoError(t, adapter.DeleteKey(ctx, "k"))

	signed, err := adapter.Sign(ctx, &quicbaas.SignRequest{KeyID: "k"})
	require.NoError(t, err)
	assert.NotNil(t, signed)
	verified, err := adapter.Verify(ctx, &quicbaas.VerifyRequest{KeyID: "k"})
	require.NoError(t, err)
	assert.NotNil(t, verified)
	encrypted, err := adapter.Encrypt(ctx, &quicbaas.EncryptRequest{KeyID: "k"})
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	decrypted, err := adapter.Decrypt(ctx, &quicbaas.DecryptRequest{KeyID: "k"})
	require.NoError(t, err)
	assert.NotNil(t, decrypted)

	assert.NotNil(t, adapter.KMS())
	assert.NotNil(t, adapter.Crypto())
	assert.NotNil(t, adapter.HealthClient())
}

func TestCoverage964_OperationsWrapSDKErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	adapter := startedAdapter(t, newFakeClient(errFakeBackend))

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"Health", func() error { _, err := adapter.Health(ctx); return err },
			ErrHealthCheckFailed{Cause: errFakeBackend}},
		{"Ping", func() error { return adapter.Ping(ctx) },
			ErrHealthCheckFailed{Cause: errFakeBackend}},
		{"GenerateKey", func() error {
			_, err := adapter.GenerateKey(ctx, &quicbaas.GenerateKeyRequest{Name: "k"})
			return err
		}, ErrKeyGenerationFailed{Name: "k", Cause: errFakeBackend}},
		{"GetKey", func() error { _, err := adapter.GetKey(ctx, "k"); return err },
			ErrKeyNotFound{KeyID: "k"}},
		{"RotateKey", func() error { _, err := adapter.RotateKey(ctx, "k"); return err },
			ErrKeyRotationFailed{KeyID: "k", Cause: errFakeBackend}},
		{"DeleteKey", func() error { return adapter.DeleteKey(ctx, "k") },
			ErrKeyDeletionFailed{KeyID: "k", Cause: errFakeBackend}},
		{"Sign", func() error {
			_, err := adapter.Sign(ctx, &quicbaas.SignRequest{KeyID: "k"})
			return err
		}, ErrSigningFailed{KeyID: "k", Cause: errFakeBackend}},
		{"Verify", func() error {
			_, err := adapter.Verify(ctx, &quicbaas.VerifyRequest{KeyID: "k"})
			return err
		}, ErrVerificationFailed{KeyID: "k", Cause: errFakeBackend}},
		{"Encrypt", func() error {
			_, err := adapter.Encrypt(ctx, &quicbaas.EncryptRequest{KeyID: "k"})
			return err
		}, ErrEncryptionFailed{KeyID: "k", Cause: errFakeBackend}},
		{"Decrypt", func() error {
			_, err := adapter.Decrypt(ctx, &quicbaas.DecryptRequest{KeyID: "k"})
			return err
		}, ErrDecryptionFailed{KeyID: "k", Cause: errFakeBackend}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			assert.Equal(t, tt.want, err)
		})
	}

	// ListKeys passes the SDK error through unwrapped.
	_, err := adapter.ListKeys(ctx)
	assert.ErrorIs(t, err, errFakeBackend)
}

func TestCoverage964_OperationsWithoutSubClients(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	adapter := startedAdapter(t, &fakeClient{security: &fakeSecurity{}})

	tests := []struct {
		name string
		call func() error
	}{
		{"Health", func() error { _, err := adapter.Health(ctx); return err }},
		{"Ping", func() error { return adapter.Ping(ctx) }},
		{"GenerateKey", func() error {
			_, err := adapter.GenerateKey(ctx, &quicbaas.GenerateKeyRequest{})
			return err
		}},
		{"GetKey", func() error { _, err := adapter.GetKey(ctx, "k"); return err }},
		{"ListKeys", func() error { _, err := adapter.ListKeys(ctx); return err }},
		{"RotateKey", func() error { _, err := adapter.RotateKey(ctx, "k"); return err }},
		{"DeleteKey", func() error { return adapter.DeleteKey(ctx, "k") }},
		{"Sign", func() error { _, err := adapter.Sign(ctx, &quicbaas.SignRequest{}); return err }},
		{"Verify", func() error { _, err := adapter.Verify(ctx, &quicbaas.VerifyRequest{}); return err }},
		{"Encrypt", func() error { _, err := adapter.Encrypt(ctx, &quicbaas.EncryptRequest{}); return err }},
		{"Decrypt", func() error { _, err := adapter.Decrypt(ctx, &quicbaas.DecryptRequest{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, ErrAdapterNotStarted, tt.call())
		})
	}
}

func TestCoverage964_Stop(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("closes the client once and rejects a restart", func(t *testing.T) {
		client := newFakeClient(nil)
		adapter := startedAdapter(t, client)

		require.NoError(t, adapter.Stop(ctx))
		assert.True(t, client.closed)
		assert.True(t, adapter.IsClosed())
		assert.Nil(t, adapter.Client())

		client.closed = false
		require.NoError(t, adapter.Stop(ctx))
		assert.False(t, client.closed, "a second Stop must not close the client again")

		assert.Equal(t, ErrAdapterClosed, adapter.Start(ctx, nil))
	})

	t.Run("returns the client close error", func(t *testing.T) {
		client := newFakeClient(nil)
		client.closeErr = errFakeBackend
		adapter := startedAdapter(t, client)

		assert.ErrorIs(t, adapter.Stop(ctx), errFakeBackend)
		assert.True(t, adapter.IsClosed())
	})

	t.Run("tolerates a nil client", func(t *testing.T) {
		adapter := startedAdapter(t, nil)
		require.NoError(t, adapter.Stop(ctx))
		assert.True(t, adapter.IsClosed())
	})
}

func TestCoverage964_StartWhenAlreadyStarted(t *testing.T) {
	t.Parallel()

	client := newFakeClient(nil)
	adapter := startedAdapter(t, client)

	// The embedded service is nil, so a second createClient would fail;
	// Start must return before reaching it and keep the existing client.
	require.NoError(t, adapter.Start(context.Background(), nil))
	assert.Same(t, client, adapter.Client())
}

func TestCoverage964_CreateClientRejectsMissingEndpoint(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	tests := []struct {
		transport Transport
		want      error
	}{
		{TransportUnix, ErrMissingUnixSocket},
		{TransportGRPC, ErrMissingAddress},
		{TransportREST, ErrMissingAddress},
		{TransportQUIC, ErrMissingAddress},
		{TransportMCP, ErrMissingAddress},
		{Transport("carrier-pigeon"), ErrUnsupportedTransport{Transport: "carrier-pigeon"}},
	}

	for _, tt := range tests {
		t.Run(tt.transport.String(), func(t *testing.T) {
			adapter, err := NewAdapter(DefaultConfig(), logger)
			require.NoError(t, err)
			// Bypass Validate to reach the createClient guards directly.
			adapter.config = &Config{Transport: tt.transport}

			assert.Equal(t, tt.want, adapter.Start(context.Background(), nil))
			assert.False(t, adapter.IsStarted())
		})
	}
}

// writeTestCA writes a self-signed CA certificate to a temp file and returns
// its path, so the SDK's TLS loader has a real PEM to parse.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "coverage-964 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestCoverage964_StartRemoteTransports(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	caPath := writeTestCA(t)
	socket := filepath.Join(t.TempDir(), "quicbaas.sock")
	tests := []struct {
		name string
		cfg  *Config
	}{
		{"unix with tls", &Config{
			Transport:      TransportUnix,
			UnixSocket:     socket,
			RequestTimeout: time.Second,
			TLS:            &TLSConfig{CACert: caPath},
		}},
		{"grpc with tls and pool", &Config{
			Transport:      TransportGRPC,
			Address:        "127.0.0.1:1",
			RequestTimeout: time.Second,
			TLS:            &TLSConfig{CACert: caPath},
			Pool:           &PoolConfig{MinConnections: 1, MaxConnections: 2, MaxIdleTime: time.Minute},
		}},
		{"rest", &Config{Transport: TransportREST, Address: "http://127.0.0.1:1", RequestTimeout: time.Second}},
		{"quic", &Config{Transport: TransportQUIC, Address: "127.0.0.1:1", RequestTimeout: time.Second}},
		{"mcp", &Config{Transport: TransportMCP, Address: "http://127.0.0.1:1", RequestTimeout: time.Second}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(DefaultConfig(), logger)
			require.NoError(t, err)
			adapter.config = tt.cfg

			require.NoError(t, adapter.Start(context.Background(), nil))
			assert.True(t, adapter.IsStarted())
			assert.NotNil(t, adapter.Client())
			require.NoError(t, adapter.Stop(context.Background()))
			assert.Nil(t, adapter.Client())
		})
	}
}

func TestCoverage964_StartRemoteFailsWithoutUsableTLS(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	missing := filepath.Join(t.TempDir(), "absent-ca.pem")
	tests := []struct {
		name string
		cfg  *Config
	}{
		// gRPC-based transports refuse to dial without TLS at all.
		{"unix without tls", &Config{Transport: TransportUnix, UnixSocket: filepath.Join(t.TempDir(), "s.sock")}},
		{"grpc without tls", &Config{Transport: TransportGRPC, Address: "127.0.0.1:1", TLS: &TLSConfig{}}},
		// Every transport fails when the configured CA file cannot be read.
		{"grpc missing ca", &Config{Transport: TransportGRPC, Address: "127.0.0.1:1", TLS: &TLSConfig{CACert: missing}}},
		{"rest missing ca", &Config{Transport: TransportREST, Address: "127.0.0.1:1", TLS: &TLSConfig{CACert: missing}}},
		{"quic missing ca", &Config{Transport: TransportQUIC, Address: "127.0.0.1:1", TLS: &TLSConfig{CACert: missing}}},
		{"mcp missing ca", &Config{Transport: TransportMCP, Address: "127.0.0.1:1", TLS: &TLSConfig{CACert: missing}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(DefaultConfig(), logger)
			require.NoError(t, err)
			adapter.config = tt.cfg

			require.Error(t, adapter.Start(context.Background(), nil))
			assert.False(t, adapter.IsStarted())
			assert.Nil(t, adapter.Client())
		})
	}
}
