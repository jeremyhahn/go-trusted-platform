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

// cov964KeyID is the one key the fake SDK clients hold; a call naming any
// other key fails, as it does against a real KMS.
const cov964KeyID = "cov964-key-7f3a"

// errFakeUnknownKey is the failure the fake SDK clients return for a key
// other than cov964KeyID.
type errFakeUnknownKey struct {
	KeyID string
}

func (e errFakeUnknownKey) Error() string {
	return "fake backend: unknown key " + e.KeyID
}

func cov964CheckKey(keyID string) error {
	if keyID != cov964KeyID {
		return errFakeUnknownKey{KeyID: keyID}
	}
	return nil
}

// cov964CtxKey tags the context of each delegated call with the operation
// name, so a test can tell the caller's context from a replacement.
type cov964CtxKey struct{}

// The populated results the fake SDK clients return; the tests assert the
// adapter hands each one back unchanged.
var (
	cov964Health = &quicbaas.HealthResponse{
		Healthy: true,
		Status:  "cov964-ready",
		Details: map[string]interface{}{"shard": "cov964"},
	}
	cov964Generated = &quicbaas.GenerateKeyResponse{
		KeyID:              cov964KeyID,
		Version:            3,
		Exportable:         true,
		DeletionProtection: true,
	}
	cov964KeyInfo = &quicbaas.KeyInfo{
		KeyID:     cov964KeyID,
		Name:      "cov964-name",
		Version:   4,
		CreatedAt: time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
		RotatedAt: time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC),
	}
	cov964Listed = &quicbaas.ListKeysResponse{
		Keys: []quicbaas.KeyInfo{*cov964KeyInfo, {KeyID: "cov964-other", Name: "other", Version: 1}},
	}
	cov964Rotated   = &quicbaas.RotateKeyResponse{KeyID: cov964KeyID, NewVersion: 5}
	cov964Signed    = &quicbaas.SignResponse{Signature: []byte{0xde, 0xad, 0xbe, 0xef}, KeyVersion: 6}
	cov964Verified  = &quicbaas.VerifyResponse{Valid: true}
	cov964Encrypted = &quicbaas.EncryptResponse{Ciphertext: []byte{0xc1, 0xc2, 0xc3}, KeyVersion: 7}
	cov964Decrypted = &quicbaas.DecryptResponse{Plaintext: []byte("cov964 plaintext")}
)

// cov964Call is what a fake SDK client received for one operation.
type cov964Call struct {
	ctx   context.Context
	keyID string
	req   any
}

// cov964Recorder records, by operation name, the arguments each fake SDK
// call received.
type cov964Recorder struct {
	calls map[string]cov964Call
}

func (r *cov964Recorder) record(ctx context.Context, op, keyID string, req any) {
	r.calls[op] = cov964Call{ctx: ctx, keyID: keyID, req: req}
}

// fakeHealth implements quicbaas.HealthClient for the two calls the adapter
// makes. The embedded interface is nil: any other call panics, which flags an
// adapter change that reaches further into the SDK than these tests expect.
type fakeHealth struct {
	quicbaas.HealthClient
	rec *cov964Recorder
	err error
}

func (f *fakeHealth) Readiness(ctx context.Context) (*quicbaas.HealthResponse, error) {
	f.rec.record(ctx, "Health", "", nil)
	if f.err != nil {
		return nil, f.err
	}
	return cov964Health, nil
}

func (f *fakeHealth) Ping(ctx context.Context) error {
	f.rec.record(ctx, "Ping", "", nil)
	return f.err
}

// fakeKMS implements the quicbaas.KMSClient calls the adapter makes.
type fakeKMS struct {
	quicbaas.KMSClient
	rec *cov964Recorder
	err error
}

func (f *fakeKMS) GenerateKey(ctx context.Context, req *quicbaas.GenerateKeyRequest) (*quicbaas.GenerateKeyResponse, error) {
	f.rec.record(ctx, "GenerateKey", "", req)
	if f.err != nil {
		return nil, f.err
	}
	return cov964Generated, nil
}

func (f *fakeKMS) GetKey(ctx context.Context, keyID string) (*quicbaas.KeyInfo, error) {
	f.rec.record(ctx, "GetKey", keyID, nil)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(keyID); err != nil {
		return nil, err
	}
	return cov964KeyInfo, nil
}

func (f *fakeKMS) ListKeys(ctx context.Context) (*quicbaas.ListKeysResponse, error) {
	f.rec.record(ctx, "ListKeys", "", nil)
	if f.err != nil {
		return nil, f.err
	}
	return cov964Listed, nil
}

func (f *fakeKMS) RotateKey(ctx context.Context, keyID string) (*quicbaas.RotateKeyResponse, error) {
	f.rec.record(ctx, "RotateKey", keyID, nil)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(keyID); err != nil {
		return nil, err
	}
	return cov964Rotated, nil
}

func (f *fakeKMS) DeleteKey(ctx context.Context, keyID string) error {
	f.rec.record(ctx, "DeleteKey", keyID, nil)
	if f.err != nil {
		return f.err
	}
	return cov964CheckKey(keyID)
}

// fakeCrypto implements the quicbaas.CryptoClient calls the adapter makes.
type fakeCrypto struct {
	quicbaas.CryptoClient
	rec *cov964Recorder
	err error
}

func (f *fakeCrypto) Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	f.rec.record(ctx, "Sign", req.KeyID, req)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(req.KeyID); err != nil {
		return nil, err
	}
	return cov964Signed, nil
}

func (f *fakeCrypto) Verify(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	f.rec.record(ctx, "Verify", req.KeyID, req)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(req.KeyID); err != nil {
		return nil, err
	}
	return cov964Verified, nil
}

func (f *fakeCrypto) Encrypt(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	f.rec.record(ctx, "Encrypt", req.KeyID, req)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(req.KeyID); err != nil {
		return nil, err
	}
	return cov964Encrypted, nil
}

func (f *fakeCrypto) Decrypt(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	f.rec.record(ctx, "Decrypt", req.KeyID, req)
	if f.err != nil {
		return nil, f.err
	}
	if err := cov964CheckKey(req.KeyID); err != nil {
		return nil, err
	}
	return cov964Decrypted, nil
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
	rec      *cov964Recorder
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
// succeed when err is nil) and record what they receive in client.rec.
func newFakeClient(err error) *fakeClient {
	rec := &cov964Recorder{calls: make(map[string]cov964Call)}
	return &fakeClient{
		security: &fakeSecurity{kms: &fakeKMS{rec: rec, err: err}, crypto: &fakeCrypto{rec: rec, err: err}},
		health:   &fakeHealth{rec: rec, err: err},
		rec:      rec,
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

	client := newFakeClient(nil)
	adapter := startedAdapter(t, client)

	// Each request is built twice: once for the call, once as the value the
	// SDK must receive, so an adapter that edits the request in place fails.
	generateReq := func() *quicbaas.GenerateKeyRequest {
		return &quicbaas.GenerateKeyRequest{Name: "cov964-name", Exportable: true, DeletionProtection: true}
	}
	signReq := func() *quicbaas.SignRequest {
		return &quicbaas.SignRequest{KeyID: cov964KeyID, Data: []byte("cov964 data to sign"), PreHashed: true}
	}
	verifyReq := func() *quicbaas.VerifyRequest {
		return &quicbaas.VerifyRequest{
			KeyID:     cov964KeyID,
			Data:      []byte("cov964 signed data"),
			Signature: []byte{0x51, 0x67},
		}
	}
	encryptReq := func() *quicbaas.EncryptRequest {
		return &quicbaas.EncryptRequest{KeyID: cov964KeyID, Plaintext: []byte("cov964 secret"), Context: []byte("aad-e")}
	}
	decryptReq := func() *quicbaas.DecryptRequest {
		return &quicbaas.DecryptRequest{KeyID: cov964KeyID, Ciphertext: []byte{0x0c, 0x1f}, Context: []byte("aad-d")}
	}

	tests := []struct {
		op    string
		call  func(ctx context.Context) (any, error)
		keyID string
		req   any
		want  any
	}{
		{"Health", func(ctx context.Context) (any, error) { return adapter.Health(ctx) }, "", nil, cov964Health},
		{"Ping", func(ctx context.Context) (any, error) { return nil, adapter.Ping(ctx) }, "", nil, nil},
		{"GenerateKey", func(ctx context.Context) (any, error) { return adapter.GenerateKey(ctx, generateReq()) },
			"", generateReq(), cov964Generated},
		{"GetKey", func(ctx context.Context) (any, error) { return adapter.GetKey(ctx, cov964KeyID) },
			cov964KeyID, nil, cov964KeyInfo},
		{"ListKeys", func(ctx context.Context) (any, error) { return adapter.ListKeys(ctx) }, "", nil, cov964Listed},
		{"RotateKey", func(ctx context.Context) (any, error) { return adapter.RotateKey(ctx, cov964KeyID) },
			cov964KeyID, nil, cov964Rotated},
		{"DeleteKey", func(ctx context.Context) (any, error) { return nil, adapter.DeleteKey(ctx, cov964KeyID) },
			cov964KeyID, nil, nil},
		{"Sign", func(ctx context.Context) (any, error) { return adapter.Sign(ctx, signReq()) },
			cov964KeyID, signReq(), cov964Signed},
		{"Verify", func(ctx context.Context) (any, error) { return adapter.Verify(ctx, verifyReq()) },
			cov964KeyID, verifyReq(), cov964Verified},
		{"Encrypt", func(ctx context.Context) (any, error) { return adapter.Encrypt(ctx, encryptReq()) },
			cov964KeyID, encryptReq(), cov964Encrypted},
		{"Decrypt", func(ctx context.Context) (any, error) { return adapter.Decrypt(ctx, decryptReq()) },
			cov964KeyID, decryptReq(), cov964Decrypted},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), cov964CtxKey{}, tt.op)

			got, err := tt.call(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "the adapter must return the SDK's own result")

			call, ok := client.rec.calls[tt.op]
			require.True(t, ok, "the adapter did not call the SDK")
			assert.Equal(t, tt.op, call.ctx.Value(cov964CtxKey{}), "the SDK must receive the caller's context")
			assert.Equal(t, tt.keyID, call.keyID)
			assert.Equal(t, tt.req, call.req)
		})
	}

	assert.Same(t, client.security.kms, adapter.KMS())
	assert.Same(t, client.security.crypto, adapter.Crypto())
	assert.Same(t, client.health, adapter.HealthClient())
}

func TestCoverage964_OperationsRejectUnknownKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	adapter := startedAdapter(t, newFakeClient(nil))
	const missing = "cov964-missing"
	unknown := errFakeUnknownKey{KeyID: missing}

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"GetKey", func() error { _, err := adapter.GetKey(ctx, missing); return err },
			ErrKeyNotFound{KeyID: missing}},
		{"RotateKey", func() error { _, err := adapter.RotateKey(ctx, missing); return err },
			ErrKeyRotationFailed{KeyID: missing, Cause: unknown}},
		{"DeleteKey", func() error { return adapter.DeleteKey(ctx, missing) },
			ErrKeyDeletionFailed{KeyID: missing, Cause: unknown}},
		{"Sign", func() error {
			_, err := adapter.Sign(ctx, &quicbaas.SignRequest{KeyID: missing})
			return err
		}, ErrSigningFailed{KeyID: missing, Cause: unknown}},
		{"Verify", func() error {
			_, err := adapter.Verify(ctx, &quicbaas.VerifyRequest{KeyID: missing})
			return err
		}, ErrVerificationFailed{KeyID: missing, Cause: unknown}},
		{"Encrypt", func() error {
			_, err := adapter.Encrypt(ctx, &quicbaas.EncryptRequest{KeyID: missing})
			return err
		}, ErrEncryptionFailed{KeyID: missing, Cause: unknown}},
		{"Decrypt", func() error {
			_, err := adapter.Decrypt(ctx, &quicbaas.DecryptRequest{KeyID: missing})
			return err
		}, ErrDecryptionFailed{KeyID: missing, Cause: unknown}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.call())
		})
	}
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
