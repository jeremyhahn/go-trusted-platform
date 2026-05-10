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

package cold_start

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// PlatformdState mirrors the canonical /healthz state strings emitted by
// pkg/api/rest/init_handlers.go.
type PlatformdState string

const (
	StateUnknown       PlatformdState = ""
	StateUninitialized PlatformdState = "uninitialized"
	StateSealed        PlatformdState = "sealed"
	StateUnsealing     PlatformdState = "unsealing"
	StateUnsealed      PlatformdState = "unsealed"
)

// HarnessConfig configures a cold-start platformd harness.
type HarnessConfig struct {
	// BinaryPath is the absolute path to the platformd binary built by
	// run-integration-tests.sh. Defaults to PLATFORM_COLD_START_BIN env
	// var when empty.
	BinaryPath string
	// DataDir is the data directory the harness manages. Defaults to
	// PLATFORM_COLD_START_DIR env var when empty.
	DataDir string
	// SocketPath is the unix socket to bind. Defaults under DataDir.
	SocketPath string
	// RESTPort, GRPCPort, QUICPort, MCPPort are the ports platformd
	// binds. Defaults match the cold-start runner ports below so they
	// do not collide with the shared daemon (which uses the standard
	// 8443/10443/9444/9445 ports).
	RESTPort int
	GRPCPort int
	QUICPort int
	MCPPort  int
	// HealthzReadyTimeout caps how long Start blocks waiting for the
	// /healthz endpoint to respond before returning ErrHealthzWaitTimeout.
	HealthzReadyTimeout time.Duration
}

// DefaultHarnessConfig returns a HarnessConfig populated from env vars
// and project defaults.
func DefaultHarnessConfig() HarnessConfig {
	bin := os.Getenv(EnvColdStartBinary)
	if bin == "" {
		bin = "/tmp/platformd"
	}
	dir := os.Getenv(EnvColdStartDataDir)
	if dir == "" {
		dir = "/tmp/platformd-cold-start"
	}
	return HarnessConfig{
		BinaryPath:          bin,
		DataDir:             dir,
		SocketPath:          filepath.Join(dir, "platformd.sock"),
		RESTPort:            18443,
		GRPCPort:            11443,
		QUICPort:            19444,
		MCPPort:             19445,
		HealthzReadyTimeout: 60 * time.Second,
	}
}

// Harness manages a single cold-start platformd lifecycle. It is safe
// for concurrent reads but Start/Stop/Restart MUST be called from the
// same goroutine that owns the test (see t.Cleanup wiring in tests).
type Harness struct {
	cfg HarnessConfig

	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	logFile *os.File
	running bool
}

// NewHarness constructs a harness with the supplied config.
func NewHarness(cfg HarnessConfig) *Harness {
	return &Harness{cfg: cfg}
}

// Config returns the harness configuration (read-only view).
func (h *Harness) Config() HarnessConfig {
	return h.cfg
}

// Start spawns platformd against the configured data dir. The data dir
// is NOT cleaned by Start; the runner script wipes the directory before
// the test process boots.
//
// Returns once /healthz answers, or ErrHealthzWaitTimeout if the daemon
// fails to bind within HealthzReadyTimeout.
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
	cmd.Env = append(os.Environ(),
		"PLATFORMD_DATA_DIR="+h.cfg.DataDir,
	)

	if err := cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		return &ErrPlatformdLaunch{Phase: "exec", Cause: err}
	}

	h.cmd = cmd
	h.cancel = cancel
	h.logFile = logFile
	h.running = true

	if err := h.waitForHealthz(ctx, h.cfg.HealthzReadyTimeout); err != nil {
		// Best-effort cleanup; the harness is still considered started
		// so the caller can capture diagnostics via Stop.
		return err
	}
	return nil
}

// Stop terminates the platformd process and closes the log handle.
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

// Restart performs Stop + Start so tests can validate the
// "barrier-sealed-on-restart" path of step 11.
func (h *Harness) Restart(ctx context.Context) error {
	if err := h.Stop(); err != nil {
		return err
	}
	return h.Start(ctx)
}

// State returns the current state reported by /healthz, or StateUnknown
// when the endpoint cannot be reached.
func (h *Harness) State(ctx context.Context) PlatformdState {
	state, _ := h.fetchHealthz(ctx)
	return state
}

// WaitState blocks until /healthz reports `want` or `timeout` elapses.
// Implemented with a context deadline + ticker driven by select; uses
// no time.Sleep per project rules.
func (h *Harness) WaitState(ctx context.Context, want PlatformdState, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var last PlatformdState
	for {
		state, err := h.fetchHealthz(deadline)
		last = state
		if err == nil && state == want {
			return nil
		}
		select {
		case <-deadline.Done():
			return &ErrHealthzWaitTimeout{
				WantState: string(want),
				LastState: string(last),
				Cause:     deadline.Err(),
			}
		case <-ticker.C:
			// next iteration polls /healthz again
		}
	}
}

// IssueAdminBundle invokes platformctl init against the running cold-start
// daemon and writes the admin bundle to the supplied path. The returned
// path is the file actually written (callers may pass "-" to stream to
// the harness's own log instead, in which case path == "-").
//
// This is a thin wrapper around `os/exec` so the harness controls the
// lifecycle instead of relying on the shared adapter pattern.
func (h *Harness) IssueAdminBundle(ctx context.Context, soPin, userPin, hostname, sans, adminBundlePath string) error {
	platformctl := os.Getenv(EnvPlatformCTLPath)
	if platformctl == "" {
		platformctl = "/tmp/platformctl"
	}
	args := []string{
		"init",
		"--barrier-strategy", "software",
		"--so-pin", soPin,
		"--user-pin", userPin,
		"--hostname", hostname,
	}
	if sans != "" {
		args = append(args, "--sans", sans)
	}
	if adminBundlePath != "" {
		args = append(args, "--admin-bundle", adminBundlePath)
	}
	cmd := exec.CommandContext(ctx, platformctl, args...)
	cmd.Stdout = h.logFile
	cmd.Stderr = h.logFile
	if err := cmd.Run(); err != nil {
		return &ErrPlatformdLaunch{Phase: "platformctl-init", Cause: err}
	}
	return nil
}

// MCPHealthURL returns the URL of the /healthz endpoint exposed on the
// MCP port (per the locked init-only contract: /healthz, /init, /unseal).
func (h *Harness) MCPHealthURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/healthz", h.cfg.MCPPort)
}

// serveArgs returns the platformd `serve` command-line arguments for
// this harness. mTLS and IAM-validation flags mirror the shared daemon
// invocation in run-integration-tests.sh so client adapters can reuse
// the same env vars.
func (h *Harness) serveArgs() []string {
	return []string{
		"serve",
		"--socket-path", h.cfg.SocketPath,
		"--rest-port", fmt.Sprintf("%d", h.cfg.RESTPort),
		"--grpc-port", fmt.Sprintf("%d", h.cfg.GRPCPort),
		"--quic-port", fmt.Sprintf("%d", h.cfg.QUICPort),
		"--mcp-port", fmt.Sprintf("%d", h.cfg.MCPPort),
		"--enable-mtls",
		"--skip-iam-validation",
		"--debug",
	}
}

// waitForHealthz drives a select-loop polling /healthz on the MCP port
// (which is exposed unconditionally per §7) until the endpoint responds
// or the deadline expires.
func (h *Harness) waitForHealthz(ctx context.Context, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		state, err := h.fetchHealthz(deadline)
		if err == nil && state != StateUnknown {
			return nil
		}
		lastErr = err
		select {
		case <-deadline.Done():
			return &ErrHealthzWaitTimeout{
				WantState: "<any-known>",
				LastState: string(state),
				Cause:     lastErr,
			}
		case <-ticker.C:
			// loop again
		}
	}
}

// fetchHealthz performs a single /healthz GET and decodes the response.
// Returns StateUnknown + the dial/read error on failure.
func (h *Harness) fetchHealthz(ctx context.Context) (PlatformdState, error) {
	url := h.MCPHealthURL()
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 2*time.Second)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return StateUnknown, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return StateUnknown, err
	}
	defer resp.Body.Close()
	var body struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return StateUnknown, err
	}
	return PlatformdState(body.State), nil
}
