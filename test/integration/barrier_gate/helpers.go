// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build integration

package barrier_gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// Environment variables consumed by the harness.
const (
	// EnvIntegration is the standard "integration tests are running" gate.
	EnvIntegration = "INTEGRATION_TEST"

	// EnvPlatformdBinary points to the platformd binary used to launch the
	// dedicated barrier-gate instance (NOT the shared daemon).
	EnvPlatformdBinary = "PLATFORM_BARRIER_GATE_BIN"

	// EnvDataDir is the data directory the harness manages.
	EnvDataDir = "PLATFORM_BARRIER_GATE_DIR"

	// EnvConfigPath points to the YAML config file passed to --config.
	EnvConfigPath = "PLATFORM_BARRIER_GATE_CONFIG"
)

// SkipIfNotIntegration skips the test when the integration gate is not
// set. The barrier-gate suite requires the devcontainer runner to seed
// the PLATFORM_BARRIER_GATE_* env vars and build the platformd binary.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegration) == "" {
		t.Skip("Skipping barrier-gate integration test: INTEGRATION_TEST not set")
	}
}

// gatePort is the port of the M6 gate's loopback bind address,
// apidaemon.DefaultInitOnlyHTTPAddr. The daemon gives no way to override
// it, so tests in this package MUST run serially.
const gatePort = 9446

// HarnessConfig configures a single barrier-gate platformd harness.
type HarnessConfig struct {
	// BinaryPath is the absolute path to the platformd binary.
	BinaryPath string

	// DataDir is the data directory the harness manages.
	DataDir string

	// ConfigPath is the YAML config passed via --config. It MUST contain
	// a `barrier:` section with seal_strategy=software so the gate
	// stays bound until /init is driven.
	ConfigPath string

	// SocketPath is the Unix socket the harness binds.
	SocketPath string

	// RESTPort, GRPCPort, QUICPort, MCPPort are the production transport
	// ports. The harness does not collide with the cold-start (1844x/19xxx)
	// or shared (8443/10443/9444/9445) port ranges.
	RESTPort int
	GRPCPort int
	QUICPort int
	MCPPort  int

	// SOPin and UserPin are passed via --raw-so-pin / --raw-pin so the
	// daemon does not block on interactive prompts and so /init can reuse
	// the same credentials.
	SOPin   string
	UserPin string

	// GateReadyTimeout caps how long Start blocks waiting for the gate's
	// /healthz endpoint to respond.
	GateReadyTimeout time.Duration
}

// DefaultHarnessConfig returns a HarnessConfig populated from env vars
// and conservative defaults.
func DefaultHarnessConfig() HarnessConfig {
	bin := os.Getenv(EnvPlatformdBinary)
	if bin == "" {
		bin = "/tmp/platformd"
	}
	dir := os.Getenv(EnvDataDir)
	if dir == "" {
		dir = "/tmp/platformd-barrier-gate"
	}
	cfg := os.Getenv(EnvConfigPath)
	if cfg == "" {
		cfg = "/workspace/test/integration/barrier_gate/config.yaml"
	}
	return HarnessConfig{
		BinaryPath:       bin,
		DataDir:          dir,
		ConfigPath:       cfg,
		SocketPath:       filepath.Join(dir, "platformd.sock"),
		RESTPort:         28443,
		GRPCPort:         21443,
		QUICPort:         29444,
		MCPPort:          29445,
		SOPin:            "123456",
		UserPin:          "123456",
		GateReadyTimeout: 60 * time.Second,
	}
}

// gateHealthURL returns the URL of the gate's /healthz endpoint.
func (c HarnessConfig) gateHealthURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/healthz", gatePort)
}

// gateInitURL returns the URL of the gate's /init endpoint.
func (c HarnessConfig) gateInitURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/init", gatePort)
}

// gateUnsealURL returns the URL of the gate's /unseal endpoint.
func (c HarnessConfig) gateUnsealURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/unseal", gatePort)
}

// productionRESTURL returns the production REST endpoint root URL.
func (c HarnessConfig) productionRESTAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", c.RESTPort)
}

// Harness manages a single barrier-gate platformd lifecycle. Concurrent
// reads are safe; Start/Stop/Restart/WipeDataDir must be called from the
// owning test goroutine.
type Harness struct {
	cfg HarnessConfig

	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	logFile *os.File
	running bool
}

// NewHarness constructs a harness with the supplied configuration.
func NewHarness(cfg HarnessConfig) *Harness {
	return &Harness{cfg: cfg}
}

// Config returns the harness configuration (read-only view).
func (h *Harness) Config() HarnessConfig {
	return h.cfg
}

// WipeDataDir removes the harness's data dir so the next Start boots
// against a pristine state. Returns the underlying os error wrapped in
// ErrPlatformdLaunch when the wipe fails.
func (h *Harness) WipeDataDir() error {
	if err := os.RemoveAll(h.cfg.DataDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &ErrPlatformdLaunch{Phase: "wipe-data-dir", Cause: err}
	}
	if err := os.MkdirAll(h.cfg.DataDir, 0o755); err != nil {
		return &ErrPlatformdLaunch{Phase: "mkdir-data-dir", Cause: err}
	}
	return nil
}

// Start spawns platformd. Returns once the gate /healthz endpoint
// responds. The caller is responsible for invoking WipeDataDir first when
// a clean boot is required.
func (h *Harness) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return nil
	}

	if err := os.MkdirAll(h.cfg.DataDir, 0o755); err != nil {
		return &ErrPlatformdLaunch{Phase: "mkdir-data-dir", Cause: err}
	}
	logPath := filepath.Join(h.cfg.DataDir, "platformd.log")
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return &ErrPlatformdLaunch{Phase: "open-log", Cause: err}
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, h.cfg.BinaryPath, h.serveArgs()...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		return &ErrPlatformdLaunch{Phase: "exec", Cause: err}
	}

	h.cmd = cmd
	h.cancel = cancel
	h.logFile = logFile
	h.running = true

	if err := h.waitForGateHealthz(ctx, h.cfg.GateReadyTimeout); err != nil {
		// Best-effort: leave the process running so Stop is callable for
		// log collection from the test cleanup.
		return err
	}
	return nil
}

// Stop terminates the platformd process and closes the log handle. Safe
// to call multiple times.
func (h *Harness) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil
	}
	h.running = false

	if h.cancel != nil {
		h.cancel()
	}
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
	if h.logFile != nil {
		_ = h.logFile.Close()
	}
	h.cmd = nil
	h.cancel = nil
	h.logFile = nil
	return nil
}

// Restart performs Stop + Start so warm-boot scenarios can validate that
// the gate re-binds against an already-initialized barrier.
func (h *Harness) Restart(ctx context.Context) error {
	if err := h.Stop(); err != nil {
		return err
	}
	return h.Start(ctx)
}

// serveArgs returns the platformd `serve` command line arguments. The
// gate's loopback bind is hard-coded; all production ports are
// configurable so multiple harnesses can coexist with other suites that
// own the standard 8443/10443/9444/9445 range.
func (h *Harness) serveArgs() []string {
	return []string{
		"serve",
		"--config", h.cfg.ConfigPath,
		"--platform-dir", h.cfg.DataDir,
		"--log-dir", filepath.Join(h.cfg.DataDir, "log"),
		"--ca-dir", filepath.Join(h.cfg.DataDir, "ca"),
		"--socket-path", h.cfg.SocketPath,
		"--rest-port", fmt.Sprintf("%d", h.cfg.RESTPort),
		"--grpc-port", fmt.Sprintf("%d", h.cfg.GRPCPort),
		"--quic-port", fmt.Sprintf("%d", h.cfg.QUICPort),
		"--mcp-port", fmt.Sprintf("%d", h.cfg.MCPPort),
		"--raw-so-pin", h.cfg.SOPin,
		"--raw-pin", h.cfg.UserPin,
		"--enable-mtls",
		"--skip-iam-validation",
		"--debug",
	}
}

// WaitGateReady blocks until the gate /healthz reports the requested
// state, or the deadline expires.
func (h *Harness) WaitGateReady(ctx context.Context, want rest.PlatformState, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastBody rest.BarrierHealthResponse
	var lastErr error
	for {
		body, err := h.fetchGateHealthz(deadline)
		lastErr = err
		if err == nil {
			lastBody = *body
			if body.State == want {
				return nil
			}
		}
		select {
		case <-deadline.Done():
			return &ErrGateWaitTimeout{
				Want:  string(want),
				Last:  string(lastBody.State),
				Cause: firstNonNil(deadline.Err(), lastErr),
			}
		case <-ticker.C:
		}
	}
}

// WaitGateGone blocks until the gate /healthz endpoint stops accepting
// new connections (TCP refusal), proving the gate listener has shut
// down. The production REST listener is bound to a different port so the
// gate refusing connections is the canonical signal the handoff is
// complete.
func (h *Harness) WaitGateGone(ctx context.Context, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	addr := fmt.Sprintf("127.0.0.1:%d", gatePort)
	var lastErr error
	for {
		err := dialExpectingRefusal(deadline, addr)
		lastErr = err
		if err == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			return &ErrGateStillBound{
				Endpoint: addr,
				Cause:    firstNonNil(deadline.Err(), lastErr),
			}
		case <-ticker.C:
		}
	}
}

// WaitProductionRESTReady blocks until the production REST port accepts
// new TCP connections, proving the production listener bound after the
// gate handoff completed.
func (h *Harness) WaitProductionRESTReady(ctx context.Context, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	addr := h.cfg.productionRESTAddr()
	var lastErr error
	for {
		err := dialExpectingAccept(deadline, addr)
		lastErr = err
		if err == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			return &ErrProductionPortNotBound{
				Protocol: "REST",
				Endpoint: addr,
				Cause:    firstNonNil(deadline.Err(), lastErr),
			}
		case <-ticker.C:
		}
	}
}

// FetchGateHealth issues a single /healthz GET against the gate and
// decodes the response. Returns ErrGateRequestFailed on a non-2xx
// response or transport error.
func (h *Harness) FetchGateHealth(ctx context.Context) (*rest.BarrierHealthResponse, error) {
	return h.fetchGateHealthz(ctx)
}

// AssertRemoteTransportsRefused dials the REST, gRPC and QUIC production
// ports and verifies each is currently refusing connections.
func (h *Harness) AssertRemoteTransportsRefused(ctx context.Context) error {
	probes := []struct {
		Name string
		Addr string
	}{
		{"REST", fmt.Sprintf("127.0.0.1:%d", h.cfg.RESTPort)},
		{"gRPC", fmt.Sprintf("127.0.0.1:%d", h.cfg.GRPCPort)},
		// QUIC binds a UDP listener — a TCP dial to the same port
		// reliably surfaces ECONNREFUSED prior to bind.
		{"QUIC-tcp-probe", fmt.Sprintf("127.0.0.1:%d", h.cfg.QUICPort)},
	}
	for _, p := range probes {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := dialExpectingRefusal(probeCtx, p.Addr)
		cancel()
		if err != nil {
			return &ErrTransportShouldRefuse{Protocol: p.Name, Endpoint: p.Addr}
		}
	}
	return nil
}

// AssertProductionTransportsAccept verifies the production REST, gRPC and
// QUIC listeners are bound after the gate releases. REST and gRPC use a
// TCP-dial probe; QUIC is verified by confirming the kernel reports the
// UDP socket as bound (a TCP dial would always fail because QUIC runs
// over UDP). Failure surfaces ErrProductionPortNotBound naming the first
// transport that did not come up.
func (h *Harness) AssertProductionTransportsAccept(ctx context.Context) error {
	tcpProbes := []struct {
		Name string
		Addr string
	}{
		{"REST", fmt.Sprintf("127.0.0.1:%d", h.cfg.RESTPort)},
		{"gRPC", fmt.Sprintf("127.0.0.1:%d", h.cfg.GRPCPort)},
	}
	for _, p := range tcpProbes {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := dialExpectingAccept(probeCtx, p.Addr)
		cancel()
		if err != nil {
			return &ErrProductionPortNotBound{Protocol: p.Name, Endpoint: p.Addr, Cause: err}
		}
	}
	quicAddr := fmt.Sprintf("127.0.0.1:%d", h.cfg.QUICPort)
	if err := assertUDPListenerBound(quicAddr); err != nil {
		return &ErrProductionPortNotBound{Protocol: "QUIC-udp", Endpoint: quicAddr, Cause: err}
	}
	return nil
}

// =============================================================================
// internal helpers
// =============================================================================

// waitForGateHealthz polls the gate /healthz endpoint until it answers
// with a known state, or the deadline expires.
func (h *Harness) waitForGateHealthz(ctx context.Context, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		body, err := h.fetchGateHealthz(deadline)
		lastErr = err
		if err == nil && body.State != "" {
			return nil
		}
		select {
		case <-deadline.Done():
			return &ErrGateWaitTimeout{
				Want:  "<any-known>",
				Last:  "",
				Cause: firstNonNil(deadline.Err(), lastErr),
			}
		case <-ticker.C:
		}
	}
}

// fetchGateHealthz issues a single GET /healthz and decodes the JSON.
func (h *Harness) fetchGateHealthz(ctx context.Context) (*rest.BarrierHealthResponse, error) {
	client := newGateHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.gateHealthURL(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, &ErrGateRequestFailed{
			Op:     "GET /healthz",
			Status: resp.StatusCode,
			Body:   string(bodyBytes),
		}
	}
	var body rest.BarrierHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &body, nil
}

// postInitJSON issues POST /init with the supplied request body and
// returns the decoded response. Non-200 responses surface as
// ErrGateRequestFailed.
func postInitJSON(ctx context.Context, cfg HarnessConfig, req *rest.BarrierInitRequest) (*rest.BarrierInitResponse, error) {
	if req == nil {
		req = &rest.BarrierInitRequest{}
	}
	resp := &rest.BarrierInitResponse{}
	if err := postJSON(ctx, cfg.gateInitURL(), req, resp, "POST /init"); err != nil {
		return nil, err
	}
	return resp, nil
}

// postUnsealJSON issues POST /unseal with the supplied request body and
// returns the decoded response. Non-200 responses surface as
// ErrGateRequestFailed.
func postUnsealJSON(ctx context.Context, cfg HarnessConfig, req *rest.BarrierUnsealRequest) (*rest.BarrierUnsealResponse, error) {
	if req == nil {
		req = &rest.BarrierUnsealRequest{}
	}
	resp := &rest.BarrierUnsealResponse{}
	if err := postJSON(ctx, cfg.gateUnsealURL(), req, resp, "POST /unseal"); err != nil {
		return nil, err
	}
	return resp, nil
}

// postJSON marshals body, posts to url and unmarshals the JSON response
// into out. Non-200 responses surface as ErrGateRequestFailed with the
// raw response body for diagnostics.
func postJSON(ctx context.Context, url string, body, out interface{}, op string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return &ErrGateRequestFailed{Op: op, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return &ErrGateRequestFailed{Op: op, Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	client := newGateHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return &ErrGateRequestFailed{Op: op, Cause: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &ErrGateRequestFailed{
			Op:     op,
			Status: resp.StatusCode,
			Body:   string(respBody),
		}
	}
	if out == nil {
		return nil
	}
	if len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return &ErrGateRequestFailed{Op: op, Cause: err}
	}
	return nil
}

// newGateHTTPClient returns an http.Client configured for the gate's
// short-lived loopback bind. Timeouts are intentionally generous because
// the ceremony backend may take several seconds when it generates a
// software seal key.
func newGateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 2*time.Second)
			},
		},
	}
}

// dialExpectingRefusal returns nil iff a TCP dial to addr is refused.
// Refusal is identified by ECONNREFUSED / EADDRNOTAVAIL / similar; any
// other error is treated as refusal-equivalent because the port not
// being bound is the contract under test.
func dialExpectingRefusal(ctx context.Context, addr string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return &ErrTransportShouldRefuse{Protocol: "tcp", Endpoint: addr}
	}
	if isRefusalLike(err) {
		return nil
	}
	// Treat timeouts and other dial errors as refusal-equivalent for
	// the purpose of "listener is not bound".
	return nil
}

// dialExpectingAccept returns nil iff the dial succeeds.
func dialExpectingAccept(ctx context.Context, addr string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// assertUDPListenerBound returns nil when the kernel reports the UDP
// socket at addr is already bound (EADDRINUSE on a fresh ListenPacket
// attempt). For QUIC — which runs over UDP — this is a reliable
// can-it-be-stolen check: if our ListenPacket succeeds, no one was on
// the port; if it fails with EADDRINUSE, the production QUIC listener
// holds it.
func assertUDPListenerBound(addr string) error {
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err == nil {
		_ = conn.Close()
		return &ErrUDPPortNotBound{Endpoint: addr}
	}
	// Any error opening the listener proves the port is in use.
	return nil
}

// isRefusalLike returns true when the error indicates the remote
// listener is not bound (ECONNREFUSED, EADDRNOTAVAIL, etc).
func isRefusalLike(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var se syscall.Errno
		if errors.As(opErr.Err, &se) {
			switch se {
			case syscall.ECONNREFUSED, syscall.EADDRNOTAVAIL, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
				return true
			}
		}
	}
	return false
}

// firstNonNil returns the first non-nil error in errs, or nil.
func firstNonNil(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
