package barrier

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// covTransportError is the typed error the fakes below return in place of
// a real SDK transport failure.
type covTransportError struct {
	op string
}

func (e *covTransportError) Error() string { return "fake transport failure: " + e.op }

// covBarrier is a recording fake of the SDK barrier client. It copies each
// secret it receives, because the Manager wipes the request buffer after
// the call returns.
type covBarrier struct {
	quicbaassdk.QRDBBarrierClient
	err error

	secret     string
	shamirReq  quicbaassdk.QRDBBarrierInitializeShamirRequest
	shamirResp *quicbaassdk.QRDBBarrierInitializeShamirResponse
	rekeyReq   quicbaassdk.QRDBBarrierRekeyRequest
	rekeyResp  *quicbaassdk.QRDBBarrierRekeyResponse
	status     *quicbaassdk.QRDBBarrierStatusResponse
}

func (f *covBarrier) BarrierInitialize(_ context.Context, req *quicbaassdk.QRDBBarrierInitializeRequest) error {
	f.secret = string(req.Secret)
	return f.err
}

func (f *covBarrier) BarrierInitializeShamir(_ context.Context, req *quicbaassdk.QRDBBarrierInitializeShamirRequest) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error) {
	f.secret = string(req.Secret)
	f.shamirReq = *req
	if f.err != nil {
		return nil, f.err
	}
	return f.shamirResp, nil
}

func (f *covBarrier) BarrierUnseal(_ context.Context, req *quicbaassdk.QRDBBarrierUnsealRequest) error {
	f.secret = string(req.Secret)
	return f.err
}

func (f *covBarrier) BarrierRekey(_ context.Context, req *quicbaassdk.QRDBBarrierRekeyRequest) (*quicbaassdk.QRDBBarrierRekeyResponse, error) {
	f.rekeyReq = *req
	if f.err != nil {
		return nil, f.err
	}
	return f.rekeyResp, nil
}

func (f *covBarrier) BarrierStatus(context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}

// covCeremony is a recording fake of the SDK ceremony client.
type covCeremony struct {
	quicbaassdk.QRDBCeremonyClient
	err error

	initReq          *quicbaassdk.QRDBCeremonyInitializeRequest
	certBeginReq     *quicbaassdk.QRDBClaimCertBeginRequest
	certCompleteReq  *quicbaassdk.QRDBClaimCertCompleteRequest
	shareBeginReq    *quicbaassdk.QRDBBeginClaimShareRequest
	shareCompleteReq *quicbaassdk.QRDBCompleteClaimShareRequest
}

func (f *covCeremony) CeremonyInitialize(_ context.Context, req *quicbaassdk.QRDBCeremonyInitializeRequest) (*quicbaassdk.QRDBCeremonyInitializeResponse, error) {
	f.initReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBCeremonyInitializeResponse{
		SPKIPin:    "spki-pin",
		CACertPEM:  "ca-pem",
		TLSCertPEM: "tls-pem",
		State:      "awaiting_claims",
		ShareCount: len(req.Officers),
	}, nil
}

func (f *covCeremony) CeremonyStatus(context.Context) (*quicbaassdk.QRDBCeremonyStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBCeremonyStatusResponse{State: "complete", SPKIPin: "spki-pin"}, nil
}

func (f *covCeremony) CeremonyClaimCertBegin(_ context.Context, req *quicbaassdk.QRDBClaimCertBeginRequest) (*quicbaassdk.QRDBClaimCertBeginResponse, error) {
	f.certBeginReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBClaimCertBeginResponse{NonceHex: "c0ffee", ExpiresAt: "2026-10-30T00:05:00Z"}, nil
}

func (f *covCeremony) CeremonyClaimCertComplete(_ context.Context, req *quicbaassdk.QRDBClaimCertCompleteRequest) (*quicbaassdk.QRDBClaimCertCompleteResponse, error) {
	f.certCompleteReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBClaimCertCompleteResponse{CertPEM: "officer-pem", CACertPEM: "ca-pem"}, nil
}

func (f *covCeremony) CeremonyBeginClaimShare(_ context.Context, req *quicbaassdk.QRDBBeginClaimShareRequest) (*quicbaassdk.QRDBBeginClaimShareResponse, error) {
	f.shareBeginReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBBeginClaimShareResponse{NonceHex: "beef", ExpiresAt: "2026-10-30T00:10:00Z"}, nil
}

func (f *covCeremony) CeremonyCompleteClaimShare(_ context.Context, req *quicbaassdk.QRDBCompleteClaimShareRequest) (*quicbaassdk.QRDBCompleteClaimShareResponse, error) {
	f.shareCompleteReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &quicbaassdk.QRDBCompleteClaimShareResponse{ShareJSON: `{"index":1}`}, nil
}

// covSecurity hands out the fakes, or fails to, as the SDK's Security()
// group would.
type covSecurity struct {
	quicbaassdk.SecurityService
	barrier     *covBarrier
	ceremony    *covCeremony
	barrierErr  error
	ceremonyErr error
}

func (s *covSecurity) Barrier() (quicbaassdk.QRDBBarrierClient, error) {
	if s.barrierErr != nil {
		return nil, s.barrierErr
	}
	return s.barrier, nil
}

func (s *covSecurity) Ceremony() (quicbaassdk.QRDBCeremonyClient, error) {
	if s.ceremonyErr != nil {
		return nil, s.ceremonyErr
	}
	return s.ceremony, nil
}

type covSDK struct {
	quicbaassdk.Client
	security *covSecurity
}

func (c covSDK) Security() quicbaassdk.SecurityService { return c.security }

// covManager builds a Manager through NewManager over fresh fakes.
func covManager(t *testing.T, cfg *Config) (*Manager, *covSecurity) {
	t.Helper()
	sec := &covSecurity{barrier: &covBarrier{}, ceremony: &covCeremony{}}
	m, err := NewManager(covSDK{security: sec}, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, sec
}

func ceremonyConfig() *Config {
	return &Config{SealStrategy: SealStrategyShamir, ShamirThreshold: 2, ShamirShares: 3}
}

// assertManagerError checks err is a ManagerError for op wrapping the
// injected transport error.
func assertManagerError(t *testing.T, err error, op string) {
	t.Helper()
	var me *ManagerError
	if !errors.As(err, &me) {
		t.Fatalf("expected *ManagerError, got %T (%v)", err, err)
	}
	if me.Op != op {
		t.Errorf("ManagerError.Op = %q, want %q", me.Op, op)
	}
	var te *covTransportError
	if !errors.As(err, &te) {
		t.Errorf("expected wrapped *covTransportError, got %v", me.Err)
	}
}

func readyOpen(m *Manager) bool {
	select {
	case <-m.ready.Load().ch:
		return true
	default:
		return false
	}
}

func TestNewManager_ValidConfigStartsSealed(t *testing.T) {
	cfg := DefaultConfig()
	m, err := NewManager(covSDK{security: &covSecurity{}}, cfg, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !m.IsSealed() || m.IsInitialized() {
		t.Errorf("new manager sealed=%v initialized=%v, want sealed and uninitialized", m.IsSealed(), m.IsInitialized())
	}
	if m.Config() != cfg {
		t.Error("Config() does not return the configuration passed in")
	}
	if m.logger == nil {
		t.Error("nil logger was not defaulted")
	}
	if readyOpen(m) {
		t.Error("ready gate open before the barrier was unsealed")
	}
}

func TestNewManager_NilConfigWithSDK(t *testing.T) {
	_, err := NewManager(covSDK{security: &covSecurity{}}, nil, nil)
	if !errors.Is(err, ErrNilConfig) {
		t.Fatalf("expected ErrNilConfig, got %v", err)
	}
	_, err = NewManager(covSDK{security: &covSecurity{}}, &Config{SealStrategy: "rot13"}, nil)
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConfigError for an unknown strategy, got %v", err)
	}
}

func TestManager_Initialize_UnsealsAndOpensGate(t *testing.T) {
	m, sec := covManager(t, DefaultConfig())
	if err := m.Initialize(context.Background(), "hunter2"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if sec.barrier.secret != "hunter2" {
		t.Errorf("SDK received secret %q, want %q", sec.barrier.secret, "hunter2")
	}
	if !m.IsInitialized() || m.IsSealed() || !readyOpen(m) {
		t.Errorf("after Initialize initialized=%v sealed=%v ready=%v", m.IsInitialized(), m.IsSealed(), readyOpen(m))
	}
	if err := m.Initialize(context.Background(), "hunter2"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("second Initialize: expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestManager_InitializeShamir_ReturnsSDKResponse(t *testing.T) {
	m, sec := covManager(t, DefaultConfig())
	want := &quicbaassdk.QRDBBarrierInitializeShamirResponse{}
	sec.barrier.shamirResp = want
	got, err := m.InitializeShamir(context.Background(), "s3cret", 2, 3)
	if err != nil {
		t.Fatalf("InitializeShamir: %v", err)
	}
	if got != want {
		t.Error("InitializeShamir did not return the SDK response")
	}
	req := sec.barrier.shamirReq
	if req.Threshold != 2 || req.TotalShares != 3 || sec.barrier.secret != "s3cret" {
		t.Errorf("SDK request threshold=%d shares=%d secret=%q", req.Threshold, req.TotalShares, sec.barrier.secret)
	}
	if !m.IsInitialized() || m.IsSealed() || !readyOpen(m) {
		t.Errorf("after InitializeShamir initialized=%v sealed=%v ready=%v", m.IsInitialized(), m.IsSealed(), readyOpen(m))
	}
}

func TestManager_Unseal_ClearsSealed(t *testing.T) {
	m, sec := covManager(t, DefaultConfig())
	if err := m.Unseal(context.Background(), "passphrase"); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if sec.barrier.secret != "passphrase" {
		t.Errorf("SDK received secret %q", sec.barrier.secret)
	}
	if m.IsSealed() || !readyOpen(m) {
		t.Errorf("after Unseal sealed=%v ready=%v", m.IsSealed(), readyOpen(m))
	}
}

func TestManager_Rekey_ForwardsSplit(t *testing.T) {
	m, sec := covManager(t, DefaultConfig())
	m.sealed.Store(false)
	want := &quicbaassdk.QRDBBarrierRekeyResponse{}
	sec.barrier.rekeyResp = want
	got, err := m.Rekey(context.Background(), 3, 5)
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if got != want {
		t.Error("Rekey did not return the SDK response")
	}
	if sec.barrier.rekeyReq.Threshold != 3 || sec.barrier.rekeyReq.Total != 5 {
		t.Errorf("SDK request %+v, want threshold 3 total 5", sec.barrier.rekeyReq)
	}
}

func TestManager_Status_ReturnsSDKStatus(t *testing.T) {
	m, sec := covManager(t, DefaultConfig())
	want := &quicbaassdk.QRDBBarrierStatusResponse{}
	sec.barrier.status = want
	got, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got != want {
		t.Error("Status did not return the SDK response")
	}
}

// TestManager_BarrierOps_SDKFailures drives every barrier operation into
// both failure points — acquiring the client and the call itself — and
// checks the typed error and that no state changed.
func TestManager_BarrierOps_SDKFailures(t *testing.T) {
	ops := []struct {
		name     string
		unsealed bool
		call     func(*Manager) error
	}{
		{"Initialize", false, func(m *Manager) error { return m.Initialize(context.Background(), "x") }},
		{"InitializeShamir", false, func(m *Manager) error {
			_, err := m.InitializeShamir(context.Background(), "x", 2, 3)
			return err
		}},
		{"Unseal", false, func(m *Manager) error { return m.Unseal(context.Background(), "x") }},
		{"Rekey", true, func(m *Manager) error {
			_, err := m.Rekey(context.Background(), 2, 3)
			return err
		}},
		{"Status", false, func(m *Manager) error {
			_, err := m.Status(context.Background())
			return err
		}},
	}
	for _, op := range ops {
		for _, failClient := range []bool{true, false} {
			name := op.name + "/call"
			if failClient {
				name = op.name + "/client"
			}
			t.Run(name, func(t *testing.T) {
				m, sec := covManager(t, DefaultConfig())
				m.sealed.Store(!op.unsealed)
				injected := &covTransportError{op: op.name}
				if failClient {
					sec.barrierErr = injected
				} else {
					sec.barrier.err = injected
				}
				assertManagerError(t, op.call(m), op.name)
				if m.IsInitialized() || m.IsSealed() == op.unsealed || readyOpen(m) {
					t.Errorf("state changed on failure: initialized=%v sealed=%v ready=%v",
						m.IsInitialized(), m.IsSealed(), readyOpen(m))
				}
			})
		}
	}
}

func TestManager_CeremonyInitialize_MapsOfficers(t *testing.T) {
	m, sec := covManager(t, ceremonyConfig())
	cfg := &CeremonyConfig{
		SOPin:     "so-pin",
		UserPin:   "user-pin",
		Threshold: 2,
		Officers: []OfficerConfig{
			{Username: "alice", CSRPEM: []byte("alice-csr")},
			{Username: "bob", CSRPEM: []byte("bob-csr")},
		},
	}
	res, err := m.CeremonyInitialize(context.Background(), cfg)
	if err != nil {
		t.Fatalf("CeremonyInitialize: %v", err)
	}
	want := CeremonyInitResult{SPKIPin: "spki-pin", CACertPEM: "ca-pem", TLSCertPEM: "tls-pem", State: "awaiting_claims", ShareCount: 2}
	if *res != want {
		t.Errorf("result %+v, want %+v", *res, want)
	}
	req := sec.ceremony.initReq
	if req.SOPin != "so-pin" || req.UserPin != "user-pin" || req.Threshold != 2 || len(req.Officers) != 2 {
		t.Fatalf("SDK request %+v", req)
	}
	if req.Officers[1].Username != "bob" || req.Officers[1].CSRPEM != "bob-csr" {
		t.Errorf("officer mapped as %+v", req.Officers[1])
	}
}

func TestManager_CeremonyInitialize_Rejections(t *testing.T) {
	cfg := &CeremonyConfig{Threshold: 2}
	tests := []struct {
		name   string
		config *Config
		ctx    context.Context
		cfg    *CeremonyConfig
		want   error
	}{
		{"nil context", ceremonyConfig(), nil, cfg, ErrNilContext},
		{"nil ceremony config", ceremonyConfig(), context.Background(), nil, ErrNilConfig},
		{"strategy without ceremony", &Config{SealStrategy: SealStrategyTPM2}, context.Background(), cfg, ErrCeremonyNotSupported},
		{"single-key passphrase", &Config{SealStrategy: SealStrategyPassphrase}, context.Background(), cfg, ErrCeremonyNotSupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, sec := covManager(t, tt.config)
			if _, err := m.CeremonyInitialize(tt.ctx, tt.cfg); !errors.Is(err, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, err)
			}
			if sec.ceremony.initReq != nil {
				t.Error("SDK was called despite the rejection")
			}
		})
	}
}

func TestManager_CeremonyQueries_ReturnSDKValues(t *testing.T) {
	m, sec := covManager(t, ceremonyConfig())
	ctx := context.Background()

	status, err := m.CeremonyStatus(ctx)
	if err != nil || *status != (CeremonyStatusInfo{State: "complete", SPKIPin: "spki-pin"}) {
		t.Errorf("CeremonyStatus = %+v, %v", status, err)
	}

	cc, err := m.BeginClaimCert(ctx, "alice")
	if err != nil || *cc != (CeremonyChallenge{NonceHex: "c0ffee", ExpiresAt: "2026-10-30T00:05:00Z"}) {
		t.Errorf("BeginClaimCert = %+v, %v", cc, err)
	}
	if sec.ceremony.certBeginReq.Username != "alice" {
		t.Errorf("BeginClaimCert sent username %q", sec.ceremony.certBeginReq.Username)
	}

	cert, err := m.CompleteClaimCert(ctx, "alice", "c0ffee", []byte("sig"))
	if err != nil || *cert != (CeremonyClaimCertResult{CertPEM: "officer-pem", CACertPEM: "ca-pem"}) {
		t.Errorf("CompleteClaimCert = %+v, %v", cert, err)
	}
	if r := sec.ceremony.certCompleteReq; r.Username != "alice" || r.NonceHex != "c0ffee" || r.Signature != "sig" {
		t.Errorf("CompleteClaimCert sent %+v", r)
	}

	sc, err := m.BeginClaimShare(ctx, "bob")
	if err != nil || *sc != (CeremonyChallenge{NonceHex: "beef", ExpiresAt: "2026-10-30T00:10:00Z"}) {
		t.Errorf("BeginClaimShare = %+v, %v", sc, err)
	}
	if sec.ceremony.shareBeginReq.Username != "bob" {
		t.Errorf("BeginClaimShare sent username %q", sec.ceremony.shareBeginReq.Username)
	}

	share, err := m.CompleteClaimShare(ctx, "bob", "beef", []byte("sig2"))
	if err != nil || string(share) != `{"index":1}` {
		t.Errorf("CompleteClaimShare = %q, %v", share, err)
	}
	if r := sec.ceremony.shareCompleteReq; r.Username != "bob" || r.NonceHex != "beef" || string(r.Signature) != "sig2" {
		t.Errorf("CompleteClaimShare sent %+v", r)
	}
}

// ceremonyOps names each ceremony call with valid arguments over ctx.
func ceremonyOps() []struct {
	name string
	call func(*Manager, context.Context) error
} {
	return []struct {
		name string
		call func(*Manager, context.Context) error
	}{
		{"CeremonyInitialize", func(m *Manager, ctx context.Context) error {
			_, err := m.CeremonyInitialize(ctx, &CeremonyConfig{Threshold: 2})
			return err
		}},
		{"CeremonyStatus", func(m *Manager, ctx context.Context) error {
			_, err := m.CeremonyStatus(ctx)
			return err
		}},
		{"BeginClaimCert", func(m *Manager, ctx context.Context) error {
			_, err := m.BeginClaimCert(ctx, "alice")
			return err
		}},
		{"CompleteClaimCert", func(m *Manager, ctx context.Context) error {
			_, err := m.CompleteClaimCert(ctx, "alice", "n", []byte("s"))
			return err
		}},
		{"BeginClaimShare", func(m *Manager, ctx context.Context) error {
			_, err := m.BeginClaimShare(ctx, "alice")
			return err
		}},
		{"CompleteClaimShare", func(m *Manager, ctx context.Context) error {
			_, err := m.CompleteClaimShare(ctx, "alice", "n", []byte("s"))
			return err
		}},
	}
}

func TestManager_CeremonyOps_SDKFailures(t *testing.T) {
	for _, op := range ceremonyOps() {
		for _, failClient := range []bool{true, false} {
			name := op.name + "/call"
			if failClient {
				name = op.name + "/client"
			}
			t.Run(name, func(t *testing.T) {
				m, sec := covManager(t, ceremonyConfig())
				injected := &covTransportError{op: op.name}
				if failClient {
					sec.ceremonyErr = injected
				} else {
					sec.ceremony.err = injected
				}
				assertManagerError(t, op.call(m, context.Background()), op.name)
			})
		}
	}
}

func TestManager_CeremonyOps_NilContext(t *testing.T) {
	for _, op := range ceremonyOps() {
		t.Run(op.name, func(t *testing.T) {
			m, _ := covManager(t, ceremonyConfig())
			if err := op.call(m, nil); !errors.Is(err, ErrNilContext) {
				t.Errorf("expected ErrNilContext, got %v", err)
			}
		})
	}
}

func TestManager_ClaimArguments_Rejected(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func(*Manager) error
		want error
	}{
		{"BeginClaimCert empty username", func(m *Manager) error {
			_, err := m.BeginClaimCert(ctx, "")
			return err
		}, ErrEmptyUsername},
		{"BeginClaimShare empty username", func(m *Manager) error {
			_, err := m.BeginClaimShare(ctx, "")
			return err
		}, ErrEmptyUsername},
		{"CompleteClaimCert empty username", func(m *Manager) error {
			_, err := m.CompleteClaimCert(ctx, "", "n", []byte("s"))
			return err
		}, ErrEmptyUsername},
		{"CompleteClaimCert empty nonce", func(m *Manager) error {
			_, err := m.CompleteClaimCert(ctx, "alice", "", []byte("s"))
			return err
		}, ErrEmptyNonce},
		{"CompleteClaimCert empty signature", func(m *Manager) error {
			_, err := m.CompleteClaimCert(ctx, "alice", "n", nil)
			return err
		}, ErrEmptySignature},
		{"CompleteClaimShare empty username", func(m *Manager) error {
			_, err := m.CompleteClaimShare(ctx, "", "n", []byte("s"))
			return err
		}, ErrEmptyUsername},
		{"CompleteClaimShare empty nonce", func(m *Manager) error {
			_, err := m.CompleteClaimShare(ctx, "alice", "", []byte("s"))
			return err
		}, ErrEmptyNonce},
		{"CompleteClaimShare empty signature", func(m *Manager) error {
			_, err := m.CompleteClaimShare(ctx, "alice", "n", []byte{})
			return err
		}, ErrEmptySignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, sec := covManager(t, ceremonyConfig())
			if err := tt.call(m); !errors.Is(err, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, err)
			}
			c := sec.ceremony
			if c.certBeginReq != nil || c.certCompleteReq != nil || c.shareBeginReq != nil || c.shareCompleteReq != nil {
				t.Error("SDK was called despite the rejection")
			}
		})
	}
}

func TestSecretBytes(t *testing.T) {
	if b := secretBytes(""); b != nil {
		t.Errorf("secretBytes(\"\") = %v, want nil", b)
	}
	if b := secretBytes("abc"); string(b) != "abc" {
		t.Errorf("secretBytes(\"abc\") = %q", b)
	}
}
