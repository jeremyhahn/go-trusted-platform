package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn/agent"
)

// The gateway admission listener is #557 work and does not exist yet, so
// these tests stand an httptest TLS server in for it, speaking the wire
// contract in pkg/sdn/gateway/services/vpn/wire.go.

// clientDevice is the host device openHostDevice returns in tests.
type clientDevice struct {
	id       string
	cert     tls.Certificate
	closeErr error
	closed   bool
}

func (d *clientDevice) ID() string                            { return d.id }
func (d *clientDevice) Certificate() (tls.Certificate, error) { return d.cert, nil }
func (d *clientDevice) Close() error {
	d.closed = true
	return d.closeErr
}
func (d *clientDevice) Quote(context.Context, []byte) (*manifest.HostAttestation, error) {
	return &manifest.HostAttestation{AKPublicKey: []byte("ak")}, nil
}

type clientPosture struct{ err error }

func (p *clientPosture) Collect(context.Context) (*gwvpn.PostureReport, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &gwvpn.PostureReport{
		SecureBoot:    gwvpn.SecureBootPosture{Available: true, Enabled: true},
		FDE:           gwvpn.FDEPosture{RootEncrypted: true},
		AgentVersion:  "test",
		KernelRelease: "6.12.0",
		CollectedAt:   time.Unix(1760325000, 0),
	}, nil
}

type clientPlane struct{ down []agent.Session }

func (p *clientPlane) Kind() gwvpn.DataPlaneKind { return gwvpn.DataPlaneMASQUE }
func (p *clientPlane) Prepare(context.Context) (gwvpn.PeerWire, error) {
	return gwvpn.PeerWire{}, nil
}
func (p *clientPlane) Up(context.Context, *gwvpn.LeaseWire) (agent.Session, error) {
	return agent.Session{Interface: "vpn0"}, nil
}
func (p *clientPlane) Down(_ context.Context, s agent.Session) error {
	p.down = append(p.down, s)
	return nil
}

// admissionListener answers the three admission routes. A non-zero
// refuseStatus refuses the admission with refusal.
type admissionListener struct {
	refuseStatus int
	refusal      gwvpn.RefusalWire
	revokeStatus int
	renewStatus  int
	renewRefusal gwvpn.RefusalWire

	mu       sync.Mutex
	admitted *gwvpn.AdmissionRequestWire
	revoked  []string
	renewals []gwvpn.AdmissionRequestWire
}

func (l *admissionListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == gwvpn.PathChallenges:
		writeJSON(w, http.StatusOK, gwvpn.ChallengeWire{Nonce: []byte("nonce-1"), DataPlanes: []gwvpn.DataPlaneKind{gwvpn.DataPlaneMASQUE}})
	case r.Method == http.MethodPost && r.URL.Path == gwvpn.PathAdmissions:
		var req gwvpn.AdmissionRequestWire
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, gwvpn.RefusalWire{Reason: gwvpn.RefusalInvalidRequest})
			return
		}
		l.mu.Lock()
		l.admitted = &req
		l.mu.Unlock()
		if l.refuseStatus != 0 {
			writeJSON(w, l.refuseStatus, l.refusal)
			return
		}
		writeJSON(w, http.StatusOK, testLease())
	case r.Method == http.MethodDelete && r.URL.Path == gwvpn.LeasePath("lease-1"):
		l.mu.Lock()
		l.revoked = append(l.revoked, "lease-1")
		l.mu.Unlock()
		if l.revokeStatus != 0 {
			writeJSON(w, l.revokeStatus, gwvpn.RefusalWire{Reason: gwvpn.RefusalLeaseStoreUnavailable})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == gwvpn.LeaseRenewPath("lease-1"):
		var req gwvpn.AdmissionRequestWire
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, gwvpn.RefusalWire{Reason: gwvpn.RefusalInvalidRequest})
			return
		}
		l.mu.Lock()
		l.renewals = append(l.renewals, req)
		l.mu.Unlock()
		if l.renewStatus != 0 {
			writeJSON(w, l.renewStatus, l.renewRefusal)
			return
		}
		lease := testLease()
		lease.ExpiresAtUnix += 3600
		lease.RenewAtUnix += 3600
		lease.Renewals = 1
		writeJSON(w, http.StatusOK, lease)
	default:
		writeJSON(w, http.StatusNotFound, gwvpn.RefusalWire{Reason: gwvpn.RefusalInvalidRequest})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func testLease() gwvpn.LeaseWire {
	return gwvpn.LeaseWire{
		ID:            "lease-1",
		DeviceID:      "laptop-1",
		TenantID:      "acme",
		Address:       "10.64.0.2",
		Zones:         []string{"management"},
		DataPlane:     gwvpn.DataPlaneMASQUE,
		ExpiresAtUnix: 1760303600,
		RenewAtUnix:   1760303000,
	}
}

// clientHarness wires the CLI verbs to an agent with a fake device and data
// plane, a real state file and the real HTTP gateway client.
type clientHarness struct {
	listener  *admissionListener
	gateway   string
	caFile    string
	statePath string
	plane     *clientPlane
	posture   *clientPosture
	out       *any
	// offered are the kinds of the data planes each verb built its agent
	// with; the agent itself brings up plane.
	offered [][]gwvpn.DataPlaneKind
	// after is the agent's renewal timer; nil is time.After.
	after func(time.Duration) <-chan time.Time

	// device is what openHostDevice opens, with the options it was given,
	// unless openErr is set.
	device  *clientDevice
	opened  []agent.HostDeviceOptions
	openErr error
}

func newClientHarness(t *testing.T) *clientHarness {
	t.Helper()
	h := &clientHarness{listener: &admissionListener{}, plane: &clientPlane{}, posture: &clientPosture{}}
	srv := httptest.NewUnstartedServer(h.listener)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.gateway = srv.Listener.Addr().String()

	dir := t.TempDir()
	h.caFile = filepath.Join(dir, "gateway-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(h.caFile, caPEM, 0o600))
	h.statePath = filepath.Join(dir, "vpn.json")

	h.device = &clientDevice{cert: clientCertificate(t)}
	origAgent, origOutput, origOpen, origForeground := newClientAgent, output, openHostDevice, foregroundContext
	openHostDevice = func(opts agent.HostDeviceOptions) (hostDevice, error) {
		h.opened = append(h.opened, opts)
		if h.openErr != nil {
			return nil, h.openErr
		}
		h.device.id = opts.ID
		return h.device, nil
	}
	newClientAgent = func(roots *x509.CertPool, device agent.Device, planes []agent.DataPlane) (*agent.Agent, error) {
		h.offered = append(h.offered, planeKinds(planes))
		return agent.New(agent.Deps{
			Device:     device,
			Posture:    h.posture,
			DataPlanes: []agent.DataPlane{h.plane},
			State:      agent.NewFileStateStore(h.statePath),
			Dial:       agent.DialHTTPGateway(roots),
			After:      h.after,
		})
	}
	var last any
	h.out = &last
	output = func(_ *cli.CommonFlags, v any) error {
		last = v
		return nil
	}
	t.Cleanup(func() {
		newClientAgent = origAgent
		output = origOutput
		openHostDevice = origOpen
		foregroundContext = origForeground
	})
	return h
}

// connected records a lease held from h's gateway in the state file.
func (h *clientHarness) connected(t *testing.T) {
	t.Helper()
	st := &agent.State{Gateway: h.gateway, Lease: testLease(), Session: agent.Session{Interface: "vpn0"}}
	require.NoError(t, agent.NewFileStateStore(h.statePath).Save(st))
}

func clientCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "laptop-1"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(4000000000, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestConnect_AdmitsAndRecordsTheLease(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile,
		"--zones", "management,ops")

	require.NoError(t, err)
	assert.Equal(t, 0, cli.ExitCode(err))
	require.NotNil(t, h.listener.admitted)
	assert.Equal(t, "laptop-1", h.listener.admitted.DeviceID)
	assert.Equal(t, []string{"management", "ops"}, h.listener.admitted.Zones)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, h.listener.admitted.DataPlane)
	st, err := agent.NewFileStateStore(h.statePath).Load()
	require.NoError(t, err)
	assert.Equal(t, gwvpn.LeaseID("lease-1"), st.Lease.ID)
	table, ok := (*h.out).(cli.TableData)
	require.True(t, ok, "table output by default")
	assert.Equal(t, []string{"lease-1", h.gateway, "10.64.0.2", "management", "masque", "vpn0",
		formatUnix(1760303600), formatUnix(1760303000)}, table.Rows[0])
}

func TestConnect_RefusalsMapToTheirExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		refusal gwvpn.RefusalWire
		want    int
		message string
	}{
		{"posture violation lists the rules", http.StatusForbidden,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalPostureViolation, Rules: []string{"secure_boot", "fde"}},
			agent.ExitPostureViolation, "secure_boot, fde"},
		{"peer not enrolled is refused", http.StatusForbidden,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalPeerNotEnrolled}, agent.ExitRefused, "refused: peer not enrolled"},
		{"503 is a refusal", http.StatusServiceUnavailable,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalPostureUnavailable}, agent.ExitRefused, "unavailable:"},
		{"pool exhausted is a refusal", http.StatusServiceUnavailable,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalPoolExhausted}, agent.ExitRefused, "unavailable: pool exhausted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newClientHarness(t)
			h.listener.refuseStatus = tt.status
			h.listener.refusal = tt.refusal

			err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile)

			require.Error(t, err)
			assert.Equal(t, tt.want, cli.ExitCode(err))
			assert.Contains(t, err.Error(), tt.message)
			assert.NoFileExists(t, h.statePath, "a refused connect records no lease")
		})
	}
}

func TestConnect_GenericFailuresExitOne(t *testing.T) {
	h := newClientHarness(t)
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, err error)
	}{
		{"missing ca file", []string{"--ca-file", filepath.Join(t.TempDir(), "absent.pem")}, func(t *testing.T, err error) {
			var loadErr cli.ErrTLSCACertLoadFailed
			assert.ErrorAs(t, err, &loadErr)
		}},
		{"ca file without PEM", []string{"--ca-file", notPEM}, func(t *testing.T, err error) {
			var invalid cli.ErrTLSCACertInvalid
			assert.ErrorAs(t, err, &invalid)
		}},
		{"gateway not trusted", nil, func(t *testing.T, err error) {
			var unreachable *agent.ErrGatewayUnreachable
			assert.ErrorAs(t, err, &unreachable)
		}},
		{"unknown factor", []string{"--ca-file", h.caFile, "--factor", "otp"}, func(t *testing.T, err error) {
			var invalid *agent.ErrInvalidOptions
			assert.ErrorAs(t, err, &invalid)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := execute(t, append([]string{"connect", "--gateway", h.gateway, "--device-id", "laptop-1"}, tt.args...)...)

			require.Error(t, err)
			assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
			tt.check(t, err)
		})
	}
}

func TestConnect_RequiresGateway(t *testing.T) {
	newClientHarness(t)

	err := execute(t, "connect")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway")
	assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
}

func TestConnect_RequiresDeviceID(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "connect", "--gateway", h.gateway)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "device-id")
	assert.Empty(t, h.opened, "the TPM is not opened")
}

func TestConnect_PresentsTheHostDeviceAndClosesIt(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-7",
		"--idevid-cert", "/etc/idevid.pem", "--ca-file", h.caFile)

	require.NoError(t, err)
	assert.Equal(t, []agent.HostDeviceOptions{{ID: "laptop-7", CertFile: "/etc/idevid.pem"}}, h.opened)
	assert.Equal(t, "laptop-7", h.listener.admitted.DeviceID)
	assert.True(t, h.device.closed)
}

func TestConnect_WithoutATPMExitsOne(t *testing.T) {
	h := newClientHarness(t)
	h.openErr = &agent.ErrNoDevice{Reason: "no platform configuration found"}

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile)

	var none *agent.ErrNoDevice
	require.ErrorAs(t, err, &none)
	assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
	assert.Nil(t, h.listener.admitted, "no gateway is contacted")
}

func TestConnect_ACloseFailureIsReported(t *testing.T) {
	h := newClientHarness(t)
	h.device.closeErr = &agent.ErrDeviceClose{Cause: errors.New("transport closed")}

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile)

	assert.ErrorIs(t, err, h.device.closeErr)
	assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
}

func TestDisconnect_RevokesAndForgetsTheLease(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)

	err := execute(t, "disconnect", "--ca-file", h.caFile)

	require.NoError(t, err)
	assert.Equal(t, []string{"lease-1"}, h.listener.revoked)
	assert.Equal(t, []agent.Session{{Interface: "vpn0"}}, h.plane.down)
	assert.NoFileExists(t, h.statePath)
	table, ok := (*h.out).(cli.TableData)
	require.True(t, ok)
	assert.Equal(t, []string{"lease-1", h.gateway, "disconnected"}, table.Rows[0])
}

func TestDisconnect_PresentsTheHostDeviceAndClosesIt(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)

	err := execute(t, "disconnect", "--ca-file", h.caFile, "--idevid-cert", "/etc/idevid.pem")

	require.NoError(t, err)
	assert.Equal(t, []agent.HostDeviceOptions{{CertFile: "/etc/idevid.pem"}}, h.opened)
	assert.True(t, h.device.closed)
}

func TestDisconnect_WithoutATPMStillTearsDownAndExitsOne(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)
	h.openErr = &agent.ErrNoDevice{Reason: "the TPM could not be opened"}

	err := execute(t, "disconnect", "--ca-file", h.caFile)

	var none *agent.ErrNoDevice
	require.ErrorAs(t, err, &none)
	assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
	assert.Empty(t, h.listener.revoked, "no revoke without the device identity")
	assert.Equal(t, []agent.Session{{Interface: "vpn0"}}, h.plane.down)
	assert.NoFileExists(t, h.statePath)
}

func TestDisconnect_NotConnectedExitsSix(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "disconnect", "--ca-file", h.caFile)

	require.Error(t, err)
	assert.Equal(t, agent.ExitNotConnected, cli.ExitCode(err))
	assert.Empty(t, h.listener.revoked, "no gateway is contacted")
}

func TestDisconnect_GatewayFailureStillTearsDown(t *testing.T) {
	h := newClientHarness(t)
	h.listener.revokeStatus = http.StatusServiceUnavailable
	h.connected(t)

	err := execute(t, "disconnect", "--ca-file", h.caFile)

	require.Error(t, err)
	assert.Equal(t, agent.ExitRefused, cli.ExitCode(err))
	assert.NoFileExists(t, h.statePath, "the local lease is forgotten either way")
}

// foreground makes connect --foreground hold its lease under a context the
// test cancels, renewing once at once and cancelling at the next wait.
func (h *clientHarness) foreground() {
	ctx, cancel := context.WithCancel(context.Background())
	foregroundContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	waits := 0
	h.after = func(time.Duration) <-chan time.Time {
		waits++
		if waits > 1 {
			cancel()
			return nil
		}
		fired := make(chan time.Time, 1)
		fired <- time.Time{}
		return fired
	}
}

func TestConnect_ForegroundRenewsUntilInterruptedThenDisconnects(t *testing.T) {
	h := newClientHarness(t)
	h.foreground()

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile, "--foreground")

	require.NoError(t, err)
	require.Len(t, h.listener.renewals, 1)
	renewal := h.listener.renewals[0]
	assert.Equal(t, "laptop-1", renewal.DeviceID)
	assert.Equal(t, []byte("nonce-1"), renewal.Nonce)
	assert.NotNil(t, renewal.Attestation, "a fresh quote")
	assert.NotNil(t, renewal.Posture, "a fresh posture report")
	assert.Equal(t, []string{"lease-1"}, h.listener.revoked, "an interrupt disconnects")
	assert.Equal(t, []agent.Session{{Interface: "vpn0"}}, h.plane.down)
	assert.NoFileExists(t, h.statePath)
}

func TestConnect_ForegroundRefusalTearsDownAndExitsWithItsCode(t *testing.T) {
	h := newClientHarness(t)
	h.foreground()
	h.listener.renewStatus = http.StatusForbidden
	h.listener.renewRefusal = gwvpn.RefusalWire{Reason: gwvpn.RefusalPostureViolation, Rules: []string{"fde"}}

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile, "--foreground")

	require.Error(t, err)
	assert.Equal(t, agent.ExitPostureViolation, cli.ExitCode(err))
	assert.Contains(t, err.Error(), "fde")
	assert.Equal(t, []agent.Session{{Interface: "vpn0"}}, h.plane.down, "the data plane comes down")
	assert.NoFileExists(t, h.statePath)
}

func TestRenew_RenewsAndRecordsTheLease(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)

	err := execute(t, "renew", "--ca-file", h.caFile, "--idevid-cert", "/etc/idevid.pem")

	require.NoError(t, err)
	assert.Equal(t, []agent.HostDeviceOptions{{CertFile: "/etc/idevid.pem"}}, h.opened)
	assert.True(t, h.device.closed)
	require.Len(t, h.listener.renewals, 1)
	assert.Equal(t, "laptop-1", h.listener.renewals[0].DeviceID, "the lease's device id")
	st, err := agent.NewFileStateStore(h.statePath).Load()
	require.NoError(t, err)
	assert.Equal(t, 1, st.Lease.Renewals)
	table, ok := (*h.out).(cli.TableData)
	require.True(t, ok)
	assert.Equal(t, formatUnix(1760307200), table.Rows[0][6], "the new expiry is printed")
}

func TestRenew_RefusalsMapToTheirExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		refusal gwvpn.RefusalWire
		want    int
		kept    bool
	}{
		{"posture violation ends the lease", http.StatusForbidden,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalPostureViolation, Rules: []string{"ima"}}, agent.ExitPostureViolation, false},
		{"attestation failure ends the lease", http.StatusForbidden,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalAttestationFailed}, agent.ExitRefused, false},
		{"a renewal not open yet keeps the lease", http.StatusConflict,
			gwvpn.RefusalWire{Reason: gwvpn.RefusalRenewalNotOpen}, agent.ExitRefused, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newClientHarness(t)
			h.connected(t)
			h.listener.renewStatus = tt.status
			h.listener.renewRefusal = tt.refusal

			err := execute(t, "renew", "--ca-file", h.caFile)

			require.Error(t, err)
			assert.Equal(t, tt.want, cli.ExitCode(err))
			if tt.kept {
				assert.FileExists(t, h.statePath)
				assert.Empty(t, h.plane.down)
				return
			}
			assert.NoFileExists(t, h.statePath)
			assert.Len(t, h.plane.down, 1)
		})
	}
}

func TestRenew_NotConnectedExitsSix(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "renew", "--ca-file", h.caFile)

	assert.Equal(t, agent.ExitNotConnected, cli.ExitCode(err))
	assert.Empty(t, h.listener.renewals)
}

func TestRenew_WithoutATPMExitsOne(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)
	h.openErr = &agent.ErrNoDevice{Reason: "the TPM could not be opened"}

	err := execute(t, "renew", "--ca-file", h.caFile)

	var none *agent.ErrNoDevice
	require.ErrorAs(t, err, &none)
	assert.Equal(t, cli.ExitGenericFailure, cli.ExitCode(err))
	assert.FileExists(t, h.statePath, "the lease is kept")
}

func TestLease_ShowsTheHeldLease(t *testing.T) {
	h := newClientHarness(t)
	h.connected(t)

	err := executeWithFlags(t, &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, "lease")

	require.NoError(t, err)
	st, ok := (*h.out).(*agent.State)
	require.True(t, ok, "structured output prints the agent state")
	assert.Equal(t, gwvpn.LeaseID("lease-1"), st.Lease.ID)
	assert.Equal(t, h.gateway, st.Gateway)
}

func TestLease_NotConnectedExitsSix(t *testing.T) {
	newClientHarness(t)

	err := execute(t, "lease")

	require.Error(t, err)
	assert.Equal(t, agent.ExitNotConnected, cli.ExitCode(err))
	var notConnected *agent.ErrNotConnected
	assert.ErrorAs(t, err, &notConnected)
}

func TestPosture_PrintsTheReportConnectSends(t *testing.T) {
	h := newClientHarness(t)

	err := executeWithFlags(t, &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, "posture")

	require.NoError(t, err)
	report, ok := (*h.out).(*gwvpn.PostureReport)
	require.True(t, ok, "structured output prints the posture report")
	assert.True(t, report.SecureBoot.Enabled)
	assert.True(t, report.FDE.RootEncrypted)
	assert.Equal(t, "6.12.0", report.KernelRelease)
	assert.Empty(t, h.opened, "posture needs no TPM")
}

func TestPosture_TableListsEveryCheck(t *testing.T) {
	h := newClientHarness(t)

	require.NoError(t, execute(t, "posture"))

	table, ok := (*h.out).(cli.TableData)
	require.True(t, ok)
	assert.Equal(t, []string{"CHECK", "VALUE"}, table.Headers)
	values := map[string]string{}
	for _, row := range table.Rows {
		values[row[0]] = row[1]
	}
	assert.Equal(t, "true", values["secure_boot.enabled"])
	assert.Equal(t, "false", values["ima.enabled"])
	assert.Equal(t, "true", values["fde.root_encrypted"])
	assert.Equal(t, "2025-10-13T03:10:00Z", values["collected_at"])
}

func TestPosture_CollectionFailureExitsOne(t *testing.T) {
	h := newClientHarness(t)
	h.posture.err = &WrappedError{Msg: "efivarfs unreadable"}

	err := execute(t, "posture")

	require.Error(t, err)
	assert.Equal(t, agent.ExitFailure, cli.ExitCode(err))
	var evidence *agent.ErrEvidence
	assert.ErrorAs(t, err, &evidence)
}

func TestNewClientAgent_DefaultBuildsWithoutDeviceOrDataPlane(t *testing.T) {
	a, err := newClientAgent(nil, nil, nil)
	require.NoError(t, err, "the default agent builds without a device or data plane")
	require.NotNil(t, a)

	_, err = a.Connect(context.Background(), agent.ConnectOptions{Gateway: "gw.example:4433", Factor: "otp"})
	var invalid *agent.ErrInvalidOptions
	assert.ErrorAs(t, err, &invalid, "options are checked before any host state is read")
}

func TestClientAgent_FactoryFailureIsWrapped(t *testing.T) {
	orig := newClientAgent
	t.Cleanup(func() { newClientAgent = orig })
	newClientAgent = func(*x509.CertPool, agent.Device, []agent.DataPlane) (*agent.Agent, error) {
		return agent.New(agent.Deps{})
	}

	_, err := clientAgent(nil, nil, nil)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	var invalid *agent.ErrInvalidOptions
	assert.ErrorAs(t, err, &invalid)
}

func TestConnect_MASQUEWithoutForegroundIsRefused(t *testing.T) {
	h := newClientHarness(t)

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile, "--data-plane", "masque")

	var foreground *ErrForegroundRequired
	require.ErrorAs(t, err, &foreground)
	assert.Equal(t, "the masque data plane lives only as long as the command: add --foreground", err.Error())
	assert.Empty(t, h.opened, "the TPM is not opened")
	assert.Nil(t, h.listener.admitted, "the gateway is not contacted")
}

func TestConnect_MASQUEInTheForegroundIsAdmitted(t *testing.T) {
	h := newClientHarness(t)
	h.foreground()

	err := execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile, "--data-plane", "masque", "--foreground")

	require.NoError(t, err)
	require.NotNil(t, h.listener.admitted)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, h.listener.admitted.DataPlane)
	assert.Equal(t, []agent.Session{{Interface: "vpn0"}}, h.plane.down, "the tunnel is held until the interrupt")
}

func TestClientVerbs_OfferMASQUEOnlyWhereATunnelCanBeHeldOrEnded(t *testing.T) {
	h := newClientHarness(t)
	h.foreground()

	require.NoError(t, execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile))
	require.NoError(t, execute(t, "renew", "--ca-file", h.caFile))
	require.NoError(t, execute(t, "lease"))
	require.NoError(t, execute(t, "posture"))
	require.NoError(t, execute(t, "disconnect", "--ca-file", h.caFile))
	require.NoError(t, execute(t, "connect", "--gateway", h.gateway, "--device-id", "laptop-1", "--ca-file", h.caFile, "--foreground"))

	require.Len(t, h.offered, 6)
	masque := func(kinds []gwvpn.DataPlaneKind) bool { return slices.Contains(kinds, gwvpn.DataPlaneMASQUE) }
	assert.False(t, masque(h.offered[0]), "connect: a TUN would die with the command")
	assert.True(t, masque(h.offered[1]), "renew must end a refused MASQUE lease")
	assert.Empty(t, h.offered[2], "lease brings nothing up")
	assert.Empty(t, h.offered[3], "posture brings nothing up")
	assert.True(t, masque(h.offered[4]), "disconnect must end a MASQUE lease")
	assert.True(t, masque(h.offered[5]), "connect --foreground holds the TUN")
}

func TestClientDataPlanes_MASQUEPresentsTheDeviceCertificate(t *testing.T) {
	certErr := &agent.ErrNoDevice{Reason: "the TPM could not be opened"}
	device := unopenedDevice{err: certErr}

	planes := clientDataPlanes(nil, device, true)

	masque := planes[len(planes)-1]
	require.Equal(t, gwvpn.DataPlaneMASQUE, masque.Kind())
	_, err := masque.Up(context.Background(), &gwvpn.LeaseWire{
		ID:        "lease-1",
		Address:   "10.8.0.2/32",
		DataPlane: gwvpn.DataPlaneMASQUE,
		Endpoint: gwvpn.EndpointWire{MASQUE: &gwvpn.MASQUEEndpointWire{
			Template: "https://gw.example/.well-known/masque/ip/",
			Routes:   []string{"10.20.0.0/16"},
		}},
	})
	assert.ErrorIs(t, err, certErr, "the session is dialled with the device's certificate")
}

func TestErrForegroundRequired_Error(t *testing.T) {
	err := &ErrForegroundRequired{DataPlane: "masque"}
	assert.Equal(t, "the masque data plane lives only as long as the command: add --foreground", err.Error())
}

// planeKinds lists the kinds of planes, in order.
func planeKinds(planes []agent.DataPlane) []gwvpn.DataPlaneKind {
	kinds := make([]gwvpn.DataPlaneKind, 0, len(planes))
	for _, p := range planes {
		kinds = append(kinds, p.Kind())
	}
	return kinds
}

func TestUnopenedDevice_ReportsWhyItCouldNotOpen(t *testing.T) {
	openErr := &agent.ErrNoDevice{Reason: "no platform configuration found"}
	device := unopenedDevice{err: openErr}

	assert.Empty(t, device.ID())
	_, err := device.Certificate()
	assert.ErrorIs(t, err, openErr)
	_, err = device.Quote(context.Background(), []byte("nonce"))
	assert.ErrorIs(t, err, openErr)
	assert.NoError(t, device.Close(), "nothing was opened")
}

func TestOpenHostDevice_WithoutATPMIsErrNoDevice(t *testing.T) {
	device, err := openHostDevice(agent.HostDeviceOptions{ConfigPaths: []string{filepath.Join(t.TempDir(), "absent.yaml")}})

	var none *agent.ErrNoDevice
	require.ErrorAs(t, err, &none)
	assert.Nil(t, device, "no typed nil behind the interface")
}
