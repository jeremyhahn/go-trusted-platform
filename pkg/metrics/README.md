# Metrics Package

The `metrics` package provides comprehensive Prometheus metrics collection for the Trusted Platform daemon and API services.

## Overview

This package implements production-grade metrics collection with support for:

- SDN operations (port state changes, flow installations)
- Certificate operations (enrollments, revocations, validations)
- API requests (HTTP/gRPC latency, error rates)
- System health (daemon uptime, goroutines, memory usage)
- TPM operations (sealing, unsealing, quote verification)
- Storage operations (key-value and object store metrics)

## Quick Start

### Basic Usage

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/metrics"

// Create metrics configuration
config := metrics.DefaultConfig()
config.Port = 9090
config.Namespace = "trusted_platform"

// Create metrics collector
collector, err := metrics.NewCollector(config)
if err != nil {
    log.Fatal(err)
}

// Start metrics server
ctx := context.Background()
if err := collector.Start(ctx); err != nil {
    log.Fatal(err)
}
defer collector.Stop(ctx)

// Access metrics
m := collector.Metrics()

// Record SDN metrics
m.SDNPortStateChanges.WithLabelValues("port1", "unauthorized", "authorized", "br0").Inc()
m.SDNFlowInstallations.WithLabelValues("br0", "0", "100", "success").Inc()

// Record certificate metrics
m.CertEnrollments.WithLabelValues("root-ca", "tls-server", "success").Inc()
m.CertOperationDuration.WithLabelValues("enroll", "root-ca").Observe(2.5)

// Record API metrics
m.HTTPRequests.WithLabelValues("GET", "/api/v1/status", "200").Inc()
m.HTTPRequestDuration.WithLabelValues("GET", "/api/v1/status").Observe(0.025)
```

### Configuration

```go
config := &metrics.Config{
    Enabled:              true,
    Namespace:            "trusted_platform",
    Subsystem:            "api", // Optional subsystem
    Path:                 "/metrics",
    Port:                 9090,
    Host:                 "localhost",
    CollectInterval:      15 * time.Second,
    EnableRuntimeMetrics: true,
    EnableProcessMetrics: true,
    Labels: map[string]string{
        "environment": "production",
        "region":      "us-west-2",
    },
}
```

## Metrics Categories

### SDN Metrics

Port state management and OpenFlow rule operations:

- `trusted_platform_sdn_port_state_changes_total` - Port state transitions
- `trusted_platform_sdn_flow_installations_total` - Flow rule installations
- `trusted_platform_sdn_flow_deletions_total` - Flow rule deletions
- `trusted_platform_sdn_flow_errors_total` - Flow operation errors
- `trusted_platform_sdn_flow_operation_duration_seconds` - Flow operation latency
- `trusted_platform_sdn_active_ports` - Currently active ports
- `trusted_platform_sdn_active_flows` - Currently active flows
- `trusted_platform_sdn_policy_evaluations_total` - Policy evaluation count
- `trusted_platform_sdn_auth_attempts_total` - Port authentication attempts
- `trusted_platform_sdn_quarantined_ports` - Quarantined port count

### Certificate Metrics

PKI and certificate lifecycle operations:

- `trusted_platform_certificate_enrollments_total` - Certificate enrollments
- `trusted_platform_certificate_revocations_total` - Certificate revocations
- `trusted_platform_certificate_renewals_total` - Certificate renewals
- `trusted_platform_certificate_validations_total` - Certificate validations
- `trusted_platform_certificate_operation_duration_seconds` - Operation latency
- `trusted_platform_certificate_expiring_soon` - Certs expiring within 30 days
- `trusted_platform_certificate_active_count` - Active certificates by type
- `trusted_platform_certificate_issuance_errors_total` - Issuance errors
- `trusted_platform_certificate_chain_depth` - Certificate chain depth distribution

### API Metrics

HTTP and gRPC request metrics:

- `trusted_platform_http_requests_total` - HTTP request count
- `trusted_platform_http_request_duration_seconds` - HTTP request latency
- `trusted_platform_http_request_size_bytes` - HTTP request size
- `trusted_platform_http_response_size_bytes` - HTTP response size
- `trusted_platform_http_active_requests` - Active HTTP requests
- `trusted_platform_http_errors_total` - HTTP errors
- `trusted_platform_grpc_requests_total` - gRPC request count
- `trusted_platform_grpc_request_duration_seconds` - gRPC request latency
- `trusted_platform_grpc_stream_messages_total` - gRPC stream messages
- `trusted_platform_grpc_active_streams` - Active gRPC streams

### System Metrics

Daemon health and resource usage:

- `trusted_platform_system_uptime_seconds` - Daemon uptime
- `trusted_platform_system_start_time_seconds` - Daemon start timestamp
- `trusted_platform_system_service_status` - Service running status (1=running, 0=stopped)
- `trusted_platform_system_goroutines` - Goroutine count
- `trusted_platform_system_memory_bytes` - Memory usage by type
- `trusted_platform_system_cpu_usage_percent` - CPU usage
- `trusted_platform_system_open_fds` - Open file descriptors
- `trusted_platform_system_database_connections` - Database connection pool stats
- `trusted_platform_system_cache_operations_total` - Cache hit/miss count
- `trusted_platform_system_errors_total` - System errors by component

### TPM Metrics

TPM operation tracking:

- `trusted_platform_tpm_operations_total` - TPM operations by type
- `trusted_platform_tpm_operation_duration_seconds` - TPM operation latency
- `trusted_platform_tpm_errors_total` - TPM errors
- `trusted_platform_tpm_quote_verifications_total` - Quote verification results

### Storage Metrics

Storage backend operations:

- `trusted_platform_storage_operations_total` - Storage operations (get/put/delete)
- `trusted_platform_storage_size_bytes` - Storage size by backend
- `trusted_platform_storage_latency_seconds` - Storage operation latency

## Integration Examples

### With REST API Server

```go
// In pkg/api/rest/server.go
import "github.com/jeremyhahn/go-trusted-platform/pkg/metrics"

func (s *Server) setupMiddleware() {
    // Add metrics middleware
    s.router.Use(s.metricsMiddleware)
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // Increment active requests
        s.metrics.HTTPActiveRequests.Inc()
        defer s.metrics.HTTPActiveRequests.Dec()

        // Wrap response writer to capture status
        ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
        next.ServeHTTP(ww, r)

        // Record metrics
        duration := time.Since(start).Seconds()
        status := strconv.Itoa(ww.Status())

        s.metrics.HTTPRequests.WithLabelValues(r.Method, r.URL.Path, status).Inc()
        s.metrics.HTTPRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
        s.metrics.HTTPRequestSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(r.ContentLength))
        s.metrics.HTTPResponseSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(ww.BytesWritten()))
    })
}
```

### With SDN Policy Engine

```go
// In pkg/sdn/policy/engine.go
func (e *Engine) SetPortState(portID string, state PortState) error {
    oldState, _ := e.stateMachine.GetState(portID)

    if err := e.stateMachine.SetState(portID, state); err != nil {
        return err
    }

    // Record metric
    e.metrics.SDNPortStateChanges.WithLabelValues(
        portID,
        string(oldState),
        string(state),
        e.bridgeName,
    ).Inc()

    return nil
}

func (e *Engine) installFlow(bridgeName string, flow *Flow) error {
    start := time.Now()

    err := e.flowController.AddFlow(bridgeName, flow)

    // Record duration
    e.metrics.SDNFlowDuration.WithLabelValues("install", bridgeName).Observe(
        time.Since(start).Seconds(),
    )

    // Record result
    status := "success"
    if err != nil {
        status = "failure"
        e.metrics.SDNFlowErrors.WithLabelValues("install", "error", bridgeName).Inc()
    }

    e.metrics.SDNFlowInstallations.WithLabelValues(
        bridgeName,
        strconv.Itoa(flow.Table),
        strconv.Itoa(flow.Priority),
        status,
    ).Inc()

    return err
}
```

### With Certificate Authority

```go
// In CA enrollment handler
func (ca *CA) EnrollCertificate(req *EnrollmentRequest) (*Certificate, error) {
    start := time.Now()

    cert, err := ca.issueCertificate(req)

    // Record duration
    ca.metrics.CertOperationDuration.WithLabelValues("enroll", ca.Name()).Observe(
        time.Since(start).Seconds(),
    )

    // Record result
    status := "success"
    if err != nil {
        status = "failure"
        ca.metrics.CertIssuanceErrors.WithLabelValues(ca.Name(), "enrollment_failed").Inc()
    }

    ca.metrics.CertEnrollments.WithLabelValues(ca.Name(), req.Type, status).Inc()

    return cert, err
}
```

## Prometheus Configuration

Example Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: 'trusted_platform'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9090']
        labels:
          service: 'platformd'
          environment: 'production'
```

## Grafana Dashboards

Example dashboard queries:

### SDN Flow Installation Rate
```promql
rate(trusted_platform_sdn_flow_installations_total[5m])
```

### Certificate Enrollment Success Rate
```promql
rate(trusted_platform_certificate_enrollments_total{status="success"}[5m]) /
rate(trusted_platform_certificate_enrollments_total[5m])
```

### API Request Latency (p95)
```promql
histogram_quantile(0.95,
  rate(trusted_platform_http_request_duration_seconds_bucket[5m])
)
```

### Memory Usage
```promql
trusted_platform_system_memory_bytes{type="heap_alloc"}
```

## Architecture

The metrics package follows best practices:

- **Zero allocation** metric recording in hot paths
- **Lock-free** counters and gauges using atomic operations
- **Histogram buckets** optimized for different metric types
- **Constant labels** for environment/region tagging
- **Automatic collection** of Go runtime metrics
- **Process metrics** for system-level monitoring
- **HTTP server** with health check endpoint

## Error Handling

All errors are typed for proper handling:

```go
if err := collector.Start(ctx); err != nil {
    var metricsErr metrics.ErrMetricsNotEnabled
    if errors.As(err, &metricsErr) {
        // Metrics disabled in config
        log.Info("Metrics collection disabled")
        return nil
    }
    return err
}
```

## Testing

Run tests with coverage:

```bash
make test-metrics
make coverage-metrics
```

## Performance

The metrics package is designed for production use:

- Sub-microsecond metric recording
- Minimal memory overhead
- Background collection for runtime metrics
- Efficient Prometheus exposition format
- HTTP/2 support for scraping
