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

package metrics

import (
	"time"
)

// Config configures Prometheus metrics collection
type Config struct {
	// Enabled enables metrics collection
	Enabled bool

	// Namespace is the metrics namespace prefix (e.g., "trusted_platform")
	Namespace string

	// Subsystem is the subsystem prefix (e.g., "api", "sdn", "ca")
	Subsystem string

	// Path is the HTTP endpoint path for metrics (default: /metrics)
	Path string

	// Port is the HTTP port to expose metrics on (default: 9090)
	Port int

	// Host is the interface to bind to (default: localhost)
	Host string

	// CollectInterval is how often to collect runtime metrics (default: 15s)
	CollectInterval time.Duration

	// EnableRuntimeMetrics enables Go runtime metrics collection
	EnableRuntimeMetrics bool

	// EnableProcessMetrics enables process metrics collection
	EnableProcessMetrics bool

	// BucketDefaults defines default histogram bucket boundaries
	BucketDefaults HistogramBuckets

	// Labels are constant labels to apply to all metrics
	Labels map[string]string
}

// HistogramBuckets defines bucket configurations for different metric types
type HistogramBuckets struct {
	// Latency buckets for API request durations (in seconds)
	Latency []float64

	// Size buckets for data sizes (in bytes)
	Size []float64

	// Duration buckets for longer-running operations (in seconds)
	Duration []float64
}

// DefaultConfig returns default metrics configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:              true,
		Namespace:            "trusted_platform",
		Subsystem:            "",
		Path:                 "/metrics",
		Port:                 9090,
		Host:                 "localhost",
		CollectInterval:      15 * time.Second,
		EnableRuntimeMetrics: true,
		EnableProcessMetrics: true,
		BucketDefaults:       DefaultHistogramBuckets(),
		Labels:               make(map[string]string),
	}
}

// DefaultHistogramBuckets returns sensible default bucket boundaries
func DefaultHistogramBuckets() HistogramBuckets {
	return HistogramBuckets{
		// API latency: 1ms to 10s
		Latency: []float64{
			0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
		},
		// Data size: 1KB to 10MB
		Size: []float64{
			1024, 10240, 102400, 524288, 1048576, 5242880, 10485760,
		},
		// Long operations: 1s to 1 hour
		Duration: []float64{
			1, 5, 10, 30, 60, 300, 600, 1800, 3600,
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Namespace == "" {
		return ErrInvalidConfiguration{Field: "Namespace", Err: &MessageError{Msg: "namespace cannot be empty"}}
	}

	if c.Path == "" {
		return ErrInvalidConfiguration{Field: "Path", Err: &MessageError{Msg: "path cannot be empty"}}
	}

	if c.Port < 1 || c.Port > 65535 {
		return ErrInvalidConfiguration{Field: "Port", Err: &MessageError{Msg: "port must be between 1 and 65535"}}
	}

	if c.Host == "" {
		return ErrInvalidConfiguration{Field: "Host", Err: &MessageError{Msg: "host cannot be empty"}}
	}

	if c.CollectInterval < time.Second {
		return ErrInvalidConfiguration{Field: "CollectInterval", Err: &MessageError{Msg: "collect interval must be at least 1 second"}}
	}

	return nil
}

// WithSubsystem returns a new config with the subsystem set
func (c *Config) WithSubsystem(subsystem string) *Config {
	cfg := *c
	cfg.Subsystem = subsystem
	return &cfg
}

// WithLabels returns a new config with additional labels
func (c *Config) WithLabels(labels map[string]string) *Config {
	cfg := *c
	cfg.Labels = make(map[string]string, len(c.Labels)+len(labels))
	for k, v := range c.Labels {
		cfg.Labels[k] = v
	}
	for k, v := range labels {
		cfg.Labels[k] = v
	}
	return &cfg
}
