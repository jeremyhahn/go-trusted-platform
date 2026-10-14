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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	// RootCAs anchors the default HTTP client's TLS verification to
	// the platform internal CA pool. When non-nil it is used as the
	// RootCAs in the fallback tls.Config that NewReporter builds when
	// HTTPClient is nil. When nil the default HTTP client falls back to
	// the operating-system trust store, preserving existing behavior.
	RootCAs *x509.CertPool

	// Collector produces the per-tick Snapshot.
	Collector Collector

	// Logger is optional; nil disables logging.
	Logger Logger
}

// Reporter pushes telemetry on a ticker.
type Reporter struct {
	cfg ReporterConfig
	// baseURL is CPBaseURL reduced to its "scheme://host" prefix, so
	// appending a route path can only ever produce that route. See
	// normalizeBaseURL.
	baseURL string
	mu      sync.Mutex
	running bool
}

// normalizeBaseURL reduces a control-plane base to the "scheme://host"
// prefix the route paths are appended to, refusing anything that would
// make that append produce a different request than it reads as.
//
// Config.Validate already refuses a base carrying a path, query or
// fragment, but NewReporter is a public constructor reachable without
// it, and the failure mode is silent rather than loud: appending
// "/api/v1/gateway/telemetry" to "https://cp.example.com?tenant=x" lands
// the whole route inside the QUERY, leaving the path "/" — so the
// reporter starts, logs nothing unusual, and pushes to the wrong
// endpoint forever. A trailing slash is the milder form, producing
// "//api/v1/..." which many servers answer with a redirect that turns a
// POST into a GET; it is normalized away rather than refused, since it
// is a harmless way to write the same base.
//
// The scheme is deliberately NOT constrained here: Config.Validate
// mandates https for a configured gateway, while tests drive the
// reporter against plaintext httptest servers.
//
// The prefix is rebuilt through url.URL.String() rather than by
// concatenating u.Host. url.Parse DECODES an RFC 6874 IPv6 zone into
// Host ("[fe80::1%25eth0]" becomes "[fe80::1%eth0]") and String()
// re-encodes it, so concatenating the raw Host yields a base that
// http.NewRequest then refuses to reparse — `invalid URL escape "%et"`,
// failing every push on an otherwise valid link-local control plane.
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", &WrappedError{Msg: "parse CPBaseURL", Err: err}
	}
	if u.Scheme == "" || u.Host == "" {
		return "", &MessageError{Msg: "CPBaseURL must be an absolute URL with a scheme and host"}
	}
	if u.User != nil {
		return "", &MessageError{Msg: "CPBaseURL must not embed userinfo credentials"}
	}
	if u.Path != "" && u.Path != "/" {
		return "", &MessageError{Msg: "CPBaseURL must not carry a path; the control-plane routes are absolute under /api/v1/gateway"}
	}
	if u.RawQuery != "" {
		return "", &MessageError{Msg: "CPBaseURL must not carry a query string"}
	}
	if u.Fragment != "" {
		return "", &MessageError{Msg: "CPBaseURL must not carry a fragment"}
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String(), nil
}

// NewReporter constructs a Reporter. The returned Reporter is not
// running — call Start to kick off the ticker.
func NewReporter(cfg ReporterConfig) (*Reporter, error) {
	if cfg.CPBaseURL == "" {
		return nil, ErrMissingField{Field: "CPBaseURL"}
	}
	if cfg.GatewayID == "" {
		return nil, ErrMissingField{Field: "GatewayID"}
	}
	if cfg.Collector == nil {
		return nil, ErrMissingField{Field: "Collector"}
	}
	if cfg.HTTPClient == nil {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    cfg.RootCAs, // nil → system roots
		}
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	baseURL, err := normalizeBaseURL(cfg.CPBaseURL)
	if err != nil {
		return nil, err
	}
	return &Reporter{cfg: cfg, baseURL: baseURL}, nil
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
		return &WrappedError{Msg: "collect", Err: err}
	}
	if snap == nil {
		return &MessageError{Msg: "collector returned nil snapshot"}
	}
	snap.GatewayID = r.cfg.GatewayID
	if snap.ReportedAt.IsZero() {
		snap.ReportedAt = time.Now().UTC()
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return &WrappedError{Msg: "marshal", Err: err}
	}
	status, err := r.send(ctx, http.MethodPost, "/api/v1/gateway/telemetry", body)
	if err != nil {
		return err
	}
	r.logInfo("telemetry posted", "gateway_id", snap.GatewayID, "status", status)
	return nil
}

// PutVPNLease records a VPN lease this gateway issued, admitted or renewed,
// with the control plane, so a restarted gateway rebuilds it.
func (r *Reporter) PutVPNLease(ctx context.Context, lease *gwstate.DesiredVPNLease) error {
	if lease == nil {
		return ErrMissingField{Field: "lease"}
	}
	body, err := json.Marshal(lease)
	if err != nil {
		return &WrappedError{Msg: "marshal", Err: err}
	}
	_, err = r.send(ctx, http.MethodPut, r.vpnLeasesPath(), body)
	return err
}

// DeleteVPNLease removes a VPN lease this gateway revoked from the control
// plane. A lease the control plane no longer holds is not an error.
func (r *Reporter) DeleteVPNLease(ctx context.Context, tenantID, leaseID string) error {
	_, err := r.send(ctx, http.MethodDelete,
		r.vpnLeasesPath()+"/"+url.PathEscape(tenantID)+"/"+url.PathEscape(leaseID), nil)
	return err
}

// vpnLeasesPath is this gateway's lease collection on the control plane.
// PathEscape keeps every ID inside its own path segment.
func (r *Reporter) vpnLeasesPath() string {
	return "/api/v1/gateway/vpn-leases/" + url.PathEscape(r.cfg.GatewayID)
}

// send makes one request to the control plane and returns the status. A
// status of 400 or above is a MessageError carrying the CP's answer.
func (r *Reporter) send(ctx context.Context, method, path string, body []byte) (int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, &WrappedError{Msg: fmt.Sprintf("CP returned %d", resp.StatusCode), Err: err}
		}
		return resp.StatusCode, &MessageError{Msg: fmt.Sprintf("CP returned %d: %s", resp.StatusCode, string(respBody))}
	}
	return resp.StatusCode, nil
}

// FetchDesiredConfig pulls the control plane's intended configuration
// for this gateway as the typed wire contract (#555). The Reconciler
// drives it on its own ticker, separate from the telemetry push. A
// document the gateway cannot represent — malformed, or carrying a
// section this build does not know — is a typed rejection, never a
// silently narrowed document.
func (r *Reporter) FetchDesiredConfig(ctx context.Context) (*gwstate.DesiredConfig, error) {
	// PathEscape, not raw interpolation: the gateway ID is configuration
	// text, and a value containing '/' or '?' would otherwise re-target
	// the request at a different control-plane route.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.baseURL+"/api/v1/gateway/desired-config/"+url.PathEscape(r.cfg.GatewayID), nil)
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
		return nil, &MessageError{Msg: fmt.Sprintf("CP returned %d: %s", resp.StatusCode, string(body))}
	}
	var envelope struct {
		Payload struct {
			GatewayID string          `json:"gateway_id"`
			Config    json.RawMessage `json:"config"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, &WrappedError{Msg: "decode", Err: err}
	}
	if len(envelope.Payload.Config) == 0 {
		return nil, &MessageError{Msg: "CP returned no desired config document"}
	}
	desired, err := gwstate.DecodeDesiredConfig(envelope.Payload.Config)
	if err != nil {
		return nil, err
	}
	if desired.GatewayID == "" {
		desired.GatewayID = envelope.Payload.GatewayID
	}
	return desired, nil
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
