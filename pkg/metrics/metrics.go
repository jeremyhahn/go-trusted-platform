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
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric definitions for the trusted platform
type Metrics struct {
	config *Config
	mu     sync.RWMutex

	// SDN Operation Metrics
	SDNPortStateChanges  *prometheus.CounterVec
	SDNFlowInstallations *prometheus.CounterVec
	SDNFlowDeletions     *prometheus.CounterVec
	SDNFlowErrors        *prometheus.CounterVec
	SDNFlowDuration      *prometheus.HistogramVec
	SDNActivePorts       prometheus.Gauge
	SDNActiveFlows       prometheus.Gauge
	SDNPolicyEvaluations *prometheus.CounterVec
	SDNAuthAttempts      *prometheus.CounterVec
	SDNQuarantinedPorts  prometheus.Gauge

	// Certificate Operation Metrics
	CertEnrollments       *prometheus.CounterVec
	CertRevocations       *prometheus.CounterVec
	CertRenewals          *prometheus.CounterVec
	CertValidations       *prometheus.CounterVec
	CertOperationDuration *prometheus.HistogramVec
	CertExpirations       prometheus.Gauge
	CertActiveCount       *prometheus.GaugeVec
	CertIssuanceErrors    *prometheus.CounterVec
	CertChainDepth        *prometheus.HistogramVec

	// API Request Metrics
	HTTPRequests        *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPRequestSize     *prometheus.HistogramVec
	HTTPResponseSize    *prometheus.HistogramVec
	HTTPActiveRequests  prometheus.Gauge
	HTTPErrors          *prometheus.CounterVec
	GRPCRequests        *prometheus.CounterVec
	GRPCRequestDuration *prometheus.HistogramVec
	GRPCStreamMessages  *prometheus.CounterVec
	GRPCActiveStreams   prometheus.Gauge

	// System Health Metrics
	DaemonUptime        prometheus.Gauge
	DaemonStartTime     prometheus.Gauge
	ServiceStatus       *prometheus.GaugeVec
	GoroutineCount      prometheus.Gauge
	MemoryUsage         *prometheus.GaugeVec
	CPUUsage            prometheus.Gauge
	OpenFileDescriptors prometheus.Gauge
	DatabaseConnections *prometheus.GaugeVec
	CacheHitRate        *prometheus.CounterVec
	ErrorRate           *prometheus.CounterVec

	// TPM Metrics
	TPMOperations         *prometheus.CounterVec
	TPMOperationDuration  *prometheus.HistogramVec
	TPMErrors             *prometheus.CounterVec
	TPMQuoteVerifications *prometheus.CounterVec

	// Storage Metrics
	StorageOperations *prometheus.CounterVec
	StorageSize       *prometheus.GaugeVec
	StorageLatency    *prometheus.HistogramVec
}

// New creates a new Metrics instance with all metrics registered
func New(config *Config) (*Metrics, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if !config.Enabled {
		return nil, ErrMetricsNotEnabled{}
	}

	m := &Metrics{
		config: config,
	}

	// Register all metrics
	if err := m.registerSDNMetrics(); err != nil {
		return nil, err
	}

	if err := m.registerCertificateMetrics(); err != nil {
		return nil, err
	}

	if err := m.registerAPIMetrics(); err != nil {
		return nil, err
	}

	if err := m.registerSystemMetrics(); err != nil {
		return nil, err
	}

	if err := m.registerTPMMetrics(); err != nil {
		return nil, err
	}

	if err := m.registerStorageMetrics(); err != nil {
		return nil, err
	}

	return m, nil
}

// registerSDNMetrics registers SDN-related metrics
func (m *Metrics) registerSDNMetrics() error {
	m.SDNPortStateChanges = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "port_state_changes_total",
			Help:        "Total number of port state changes",
			ConstLabels: m.config.Labels,
		},
		[]string{"port_id", "from_state", "to_state", "bridge"},
	)

	m.SDNFlowInstallations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "flow_installations_total",
			Help:        "Total number of OpenFlow rule installations",
			ConstLabels: m.config.Labels,
		},
		[]string{"bridge", "table", "priority", "status"},
	)

	m.SDNFlowDeletions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "flow_deletions_total",
			Help:        "Total number of OpenFlow rule deletions",
			ConstLabels: m.config.Labels,
		},
		[]string{"bridge", "table", "status"},
	)

	m.SDNFlowErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "flow_errors_total",
			Help:        "Total number of flow operation errors",
			ConstLabels: m.config.Labels,
		},
		[]string{"operation", "error_type", "bridge"},
	)

	m.SDNFlowDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "flow_operation_duration_seconds",
			Help:        "Duration of flow operations in seconds",
			Buckets:     m.config.BucketDefaults.Latency,
			ConstLabels: m.config.Labels,
		},
		[]string{"operation", "bridge"},
	)

	m.SDNActivePorts = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "active_ports",
			Help:        "Number of active ports",
			ConstLabels: m.config.Labels,
		},
	)

	m.SDNActiveFlows = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "active_flows",
			Help:        "Number of active OpenFlow rules",
			ConstLabels: m.config.Labels,
		},
	)

	m.SDNPolicyEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "policy_evaluations_total",
			Help:        "Total number of policy evaluations",
			ConstLabels: m.config.Labels,
		},
		[]string{"port_id", "result", "reason"},
	)

	m.SDNAuthAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "auth_attempts_total",
			Help:        "Total number of port authentication attempts",
			ConstLabels: m.config.Labels,
		},
		[]string{"port_id", "result", "method"},
	)

	m.SDNQuarantinedPorts = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "sdn",
			Name:        "quarantined_ports",
			Help:        "Number of quarantined ports",
			ConstLabels: m.config.Labels,
		},
	)

	return nil
}

// registerCertificateMetrics registers certificate operation metrics
func (m *Metrics) registerCertificateMetrics() error {
	m.CertEnrollments = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "enrollments_total",
			Help:        "Total number of certificate enrollments",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "type", "status"},
	)

	m.CertRevocations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "revocations_total",
			Help:        "Total number of certificate revocations",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "reason"},
	)

	m.CertRenewals = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "renewals_total",
			Help:        "Total number of certificate renewals",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "status"},
	)

	m.CertValidations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "validations_total",
			Help:        "Total number of certificate validations",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "result"},
	)

	m.CertOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "operation_duration_seconds",
			Help:        "Duration of certificate operations in seconds",
			Buckets:     m.config.BucketDefaults.Duration,
			ConstLabels: m.config.Labels,
		},
		[]string{"operation", "ca"},
	)

	m.CertExpirations = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "expiring_soon",
			Help:        "Number of certificates expiring within 30 days",
			ConstLabels: m.config.Labels,
		},
	)

	m.CertActiveCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "active_count",
			Help:        "Number of active certificates",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "type"},
	)

	m.CertIssuanceErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "issuance_errors_total",
			Help:        "Total number of certificate issuance errors",
			ConstLabels: m.config.Labels,
		},
		[]string{"ca", "error_type"},
	)

	m.CertChainDepth = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "certificate",
			Name:        "chain_depth",
			Help:        "Certificate chain depth distribution",
			Buckets:     []float64{1, 2, 3, 4, 5, 6, 7, 8},
			ConstLabels: m.config.Labels,
		},
		[]string{"ca"},
	)

	return nil
}

// registerAPIMetrics registers API request metrics
func (m *Metrics) registerAPIMetrics() error {
	m.HTTPRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "requests_total",
			Help:        "Total number of HTTP requests",
			ConstLabels: m.config.Labels,
		},
		[]string{"method", "path", "status"},
	)

	m.HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "request_duration_seconds",
			Help:        "HTTP request duration in seconds",
			Buckets:     m.config.BucketDefaults.Latency,
			ConstLabels: m.config.Labels,
		},
		[]string{"method", "path"},
	)

	m.HTTPRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "request_size_bytes",
			Help:        "HTTP request size in bytes",
			Buckets:     m.config.BucketDefaults.Size,
			ConstLabels: m.config.Labels,
		},
		[]string{"method", "path"},
	)

	m.HTTPResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "response_size_bytes",
			Help:        "HTTP response size in bytes",
			Buckets:     m.config.BucketDefaults.Size,
			ConstLabels: m.config.Labels,
		},
		[]string{"method", "path"},
	)

	m.HTTPActiveRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "active_requests",
			Help:        "Number of active HTTP requests",
			ConstLabels: m.config.Labels,
		},
	)

	m.HTTPErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "http",
			Name:        "errors_total",
			Help:        "Total number of HTTP errors",
			ConstLabels: m.config.Labels,
		},
		[]string{"method", "path", "error_type"},
	)

	m.GRPCRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "grpc",
			Name:        "requests_total",
			Help:        "Total number of gRPC requests",
			ConstLabels: m.config.Labels,
		},
		[]string{"service", "method", "status"},
	)

	m.GRPCRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "grpc",
			Name:        "request_duration_seconds",
			Help:        "gRPC request duration in seconds",
			Buckets:     m.config.BucketDefaults.Latency,
			ConstLabels: m.config.Labels,
		},
		[]string{"service", "method"},
	)

	m.GRPCStreamMessages = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "grpc",
			Name:        "stream_messages_total",
			Help:        "Total number of gRPC stream messages",
			ConstLabels: m.config.Labels,
		},
		[]string{"service", "method", "direction"},
	)

	m.GRPCActiveStreams = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "grpc",
			Name:        "active_streams",
			Help:        "Number of active gRPC streams",
			ConstLabels: m.config.Labels,
		},
	)

	return nil
}

// registerSystemMetrics registers system health metrics
func (m *Metrics) registerSystemMetrics() error {
	m.DaemonUptime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "uptime_seconds",
			Help:        "Daemon uptime in seconds",
			ConstLabels: m.config.Labels,
		},
	)

	m.DaemonStartTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "start_time_seconds",
			Help:        "Daemon start time as Unix timestamp",
			ConstLabels: m.config.Labels,
		},
	)

	m.ServiceStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "service_status",
			Help:        "Service status (1=running, 0=stopped)",
			ConstLabels: m.config.Labels,
		},
		[]string{"service"},
	)

	m.GoroutineCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "goroutines",
			Help:        "Number of goroutines",
			ConstLabels: m.config.Labels,
		},
	)

	m.MemoryUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "memory_bytes",
			Help:        "Memory usage in bytes",
			ConstLabels: m.config.Labels,
		},
		[]string{"type"},
	)

	m.CPUUsage = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "cpu_usage_percent",
			Help:        "CPU usage percentage",
			ConstLabels: m.config.Labels,
		},
	)

	m.OpenFileDescriptors = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "open_fds",
			Help:        "Number of open file descriptors",
			ConstLabels: m.config.Labels,
		},
	)

	m.DatabaseConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "database_connections",
			Help:        "Number of database connections",
			ConstLabels: m.config.Labels,
		},
		[]string{"database", "state"},
	)

	m.CacheHitRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "cache_operations_total",
			Help:        "Total number of cache operations",
			ConstLabels: m.config.Labels,
		},
		[]string{"cache", "result"},
	)

	m.ErrorRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "system",
			Name:        "errors_total",
			Help:        "Total number of system errors",
			ConstLabels: m.config.Labels,
		},
		[]string{"component", "error_type"},
	)

	return nil
}

// registerTPMMetrics registers TPM operation metrics
func (m *Metrics) registerTPMMetrics() error {
	m.TPMOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "tpm",
			Name:        "operations_total",
			Help:        "Total number of TPM operations",
			ConstLabels: m.config.Labels,
		},
		[]string{"operation", "status"},
	)

	m.TPMOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "tpm",
			Name:        "operation_duration_seconds",
			Help:        "TPM operation duration in seconds",
			Buckets:     m.config.BucketDefaults.Latency,
			ConstLabels: m.config.Labels,
		},
		[]string{"operation"},
	)

	m.TPMErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "tpm",
			Name:        "errors_total",
			Help:        "Total number of TPM errors",
			ConstLabels: m.config.Labels,
		},
		[]string{"operation", "error_type"},
	)

	m.TPMQuoteVerifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "tpm",
			Name:        "quote_verifications_total",
			Help:        "Total number of TPM quote verifications",
			ConstLabels: m.config.Labels,
		},
		[]string{"result"},
	)

	return nil
}

// registerStorageMetrics registers storage operation metrics
func (m *Metrics) registerStorageMetrics() error {
	m.StorageOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "storage",
			Name:        "operations_total",
			Help:        "Total number of storage operations",
			ConstLabels: m.config.Labels,
		},
		[]string{"backend", "operation", "status"},
	)

	m.StorageSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "storage",
			Name:        "size_bytes",
			Help:        "Storage size in bytes",
			ConstLabels: m.config.Labels,
		},
		[]string{"backend", "type"},
	)

	m.StorageLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   m.config.Namespace,
			Subsystem:   "storage",
			Name:        "latency_seconds",
			Help:        "Storage operation latency in seconds",
			Buckets:     m.config.BucketDefaults.Latency,
			ConstLabels: m.config.Labels,
		},
		[]string{"backend", "operation"},
	)

	return nil
}

// Config returns the metrics configuration
func (m *Metrics) Config() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// MetricName constructs a full metric name
func (m *Metrics) MetricName(subsystem, name string) string {
	if subsystem == "" {
		return fmt.Sprintf("%s_%s", m.config.Namespace, name)
	}
	return fmt.Sprintf("%s_%s_%s", m.config.Namespace, subsystem, name)
}
