// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

// DefaultMetricsListen is where the metrics endpoint binds when the
// `metrics:` section enables it without naming an address. Loopback by
// default: a scrape target is opened deliberately, never by omission.
const DefaultMetricsListen = "127.0.0.1:9169"

// metricsPath is the scrape path.
const metricsPath = "/metrics"

// metricsShutdownTimeout bounds the metrics listener's graceful drain.
const metricsShutdownTimeout = 5 * time.Second

// metricsReadHeaderTimeout bounds how long a scrape may take to send its
// request headers.
const metricsReadHeaderTimeout = 10 * time.Second

// MetricsConfig is the gatewayd `metrics:` section: the Prometheus
// endpoint exporting the same telemetry snapshot the control plane
// receives (#594).
type MetricsConfig struct {
	// Enabled turns the endpoint on. Off by default.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Listen is the address to bind, default 127.0.0.1:9169.
	Listen string `yaml:"listen,omitempty" json:"listen,omitempty" mapstructure:"listen"`
}

// EffectiveListen returns the configured address or the loopback default.
func (c *MetricsConfig) EffectiveListen() string {
	if c == nil || c.Listen == "" {
		return DefaultMetricsListen
	}
	return c.Listen
}

// Validate refuses a section that names an address the daemon cannot bind.
func (c *MetricsConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if _, _, err := net.SplitHostPort(c.EffectiveListen()); err != nil {
		return &ErrMetricsListen{Address: c.EffectiveListen(), Cause: err}
	}
	return nil
}

// MetricsServer serves the gateway's Prometheus metrics over HTTP.
type MetricsServer struct {
	server   *http.Server
	listener net.Listener
	logger   *slog.Logger
}

// BuildMetricsServer prepares the metrics endpoint from the `metrics:`
// section. It returns nil when the section is absent or disabled, and a
// typed error when the address cannot be bound — a scrape endpoint the
// operator asked for and did not get is a failure, not a warning.
func BuildMetricsServer(cfg *MetricsConfig, source gateway.SnapshotSource, logger *slog.Logger) (*MetricsServer, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if source == nil {
		return nil, &ErrMetricsListen{Address: cfg.EffectiveListen(), Cause: errors.New("no gateway to collect from")}
	}
	registry := prometheus.NewRegistry()
	if err := registry.Register(gateway.NewCollector(source)); err != nil {
		return nil, &ErrMetricsListen{Address: cfg.EffectiveListen(), Cause: err}
	}
	listener, err := net.Listen("tcp", cfg.EffectiveListen())
	if err != nil {
		return nil, &ErrMetricsListen{Address: cfg.EffectiveListen(), Cause: err}
	}
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	return &MetricsServer{
		server:   &http.Server{Handler: mux, ReadHeaderTimeout: metricsReadHeaderTimeout},
		listener: listener,
		logger:   logger,
	}, nil
}

// Addr is the address the endpoint bound, which is what an operator needs
// when the configuration asked for port 0.
func (s *MetricsServer) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Serve runs the endpoint until Shutdown is called. A closed server is not
// an error.
func (s *MetricsServer) Serve() error {
	if s == nil {
		return nil
	}
	if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return &ErrMetricsServe{Address: s.Addr(), Cause: err}
	}
	return nil
}

// Shutdown drains the endpoint.
func (s *MetricsServer) Shutdown() error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		return &ErrMetricsServe{Address: s.Addr(), Cause: err}
	}
	return nil
}

// ErrMetricsListen reports a metrics endpoint that could not be prepared.
type ErrMetricsListen struct {
	Address string
	Cause   error
}

// Error implements the error interface.
func (e *ErrMetricsListen) Error() string {
	return "gatewayd metrics: cannot listen on " + e.Address + ": " + e.Cause.Error()
}

// Unwrap returns the bind failure.
func (e *ErrMetricsListen) Unwrap() error { return e.Cause }

// ErrMetricsServe reports a metrics endpoint that failed while serving.
type ErrMetricsServe struct {
	Address string
	Cause   error
}

// Error implements the error interface.
func (e *ErrMetricsServe) Error() string {
	return "gatewayd metrics: serving " + e.Address + " failed: " + e.Cause.Error()
}

// Unwrap returns the serving failure.
func (e *ErrMetricsServe) Unwrap() error { return e.Cause }
