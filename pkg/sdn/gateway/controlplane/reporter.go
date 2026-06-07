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

// Package controlplane is the gatewayd-side client of the CP's
// gateway control plane. It periodically POSTs a Snapshot of the
// local gatewayd state to /api/v1/gateway/telemetry and pulls the
// desired configuration from /api/v1/gateway/desired-config so the
// reload loop can reconcile drift.
//
// The reporter holds the only goroutine in this package; it runs
// until the supplied context is cancelled. mTLS auth (the gateway's
// IDevID-derived client cert) carries the identity claim — there is
// no separate JWT path.
package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// Collector produces a current Snapshot for the local gatewayd. The
// gateway-side reload loop owns the data sources (BGP table, IPAM
// pools, PXE service, DHCP leases) and assembles them into the
// Snapshot shape consumed by the CP.
type Collector interface {
	Collect(ctx context.Context) (*gwstate.Snapshot, error)
}

// Logger is the narrow logging surface the reporter uses. Defined
// here so callers can pass any implementation (slog wrapper, the
// project's logging.Logger, etc.) without importing it.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// ReporterConfig configures the periodic telemetry reporter.
type ReporterConfig struct {
	// CPBaseURL is the platform CP's API base (e.g.
	// https://cp.example.com:8443). The reporter appends
	// /api/v1/gateway/telemetry to POST and
	// /api/v1/gateway/desired-config/<id> to GET.
	CPBaseURL string

	// GatewayID identifies this gatewayd. Must match the gateway_id
	// the CP authorizes for the supplied mTLS client cert.
	GatewayID string

	// Interval is the duration between telemetry POSTs. Reasonable
	// defaults: 15s during active reconciliation, 60s steady state.
	Interval time.Duration

	// HTTPClient is the bound mTLS client. Callers pass a client
	// pre-configured with the gateway's IDevID-derived cert so the
	// CP can verify the request identity at TLS-handshake time.
	HTTPClient *http.Client

	// Collector produces the per-tick Snapshot.
	Collector Collector

	// Logger is optional; nil disables logging.
	Logger Logger
}

// Reporter pushes telemetry on a ticker.
type Reporter struct {
	cfg     ReporterConfig
	mu      sync.Mutex
	running bool
}

// NewReporter constructs a Reporter. The returned Reporter is not
// running — call Start to kick off the ticker.
func NewReporter(cfg ReporterConfig) (*Reporter, error) {
	if cfg.CPBaseURL == "" {
		return nil, fmt.Errorf("controlplane: CPBaseURL is required")
	}
	if cfg.GatewayID == "" {
		return nil, fmt.Errorf("controlplane: GatewayID is required")
	}
	if cfg.Collector == nil {
		return nil, fmt.Errorf("controlplane: Collector is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Reporter{cfg: cfg}, nil
}

// Start runs the reporter loop until ctx is cancelled. It is safe
// to call Start once; subsequent calls return ErrAlreadyRunning.
func (r *Reporter) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return ErrAlreadyRunning{}
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	// Push immediately so the CP sees us during boot, then on
	// every Interval tick.
	if err := r.pushOnce(ctx); err != nil {
		r.logWarn("initial telemetry push failed", "error", err.Error())
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.pushOnce(ctx); err != nil {
				r.logWarn("telemetry push failed", "error", err.Error())
			}
		}
	}
}

// pushOnce collects + posts a single Snapshot. Public so tests can
// drive it deterministically without spinning up the ticker.
func (r *Reporter) pushOnce(ctx context.Context) error {
	snap, err := r.cfg.Collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	if snap == nil {
		return fmt.Errorf("collector returned nil snapshot")
	}
	snap.GatewayID = r.cfg.GatewayID
	if snap.ReportedAt.IsZero() {
		snap.ReportedAt = time.Now().UTC()
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.cfg.CPBaseURL+"/api/v1/gateway/telemetry",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("CP returned %d: %s", resp.StatusCode, string(respBody))
	}
	r.logInfo("telemetry posted", "gateway_id", snap.GatewayID, "status", resp.StatusCode)
	return nil
}

// FetchDesiredConfig pulls the CP-side intended configuration for
// this gateway. Callers invoke it from the reload loop on a
// separate (possibly slower) ticker than the telemetry push.
func (r *Reporter) FetchDesiredConfig(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.cfg.CPBaseURL+"/api/v1/gateway/desired-config/"+r.cfg.GatewayID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("CP returned %d: %s", resp.StatusCode, string(body))
	}
	var envelope struct {
		Payload struct {
			GatewayID string                 `json:"gateway_id"`
			Config    map[string]interface{} `json:"config"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return envelope.Payload.Config, nil
}

func (r *Reporter) logInfo(msg string, args ...any) {
	if r.cfg.Logger != nil {
		r.cfg.Logger.Info(msg, args...)
	}
}

func (r *Reporter) logWarn(msg string, args ...any) {
	if r.cfg.Logger != nil {
		r.cfg.Logger.Warn(msg, args...)
	}
}

// ErrAlreadyRunning is returned when Start is called on a Reporter
// whose loop is already active.
type ErrAlreadyRunning struct{}

func (ErrAlreadyRunning) Error() string {
	return "controlplane: reporter already running"
}
