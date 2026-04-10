# Health Check Framework

Health monitoring and probes for platform services.

## Overview

The health package provides Kubernetes-style health checks for platform components:

- **Liveness probes** - Determine if a component is alive
- **Readiness probes** - Determine if a component is ready to serve traffic
- **Startup probes** - Track initial startup progress

## Package Structure

```
pkg/health/
├── types.go      # HealthStatus, ComponentHealth, SystemHealth
├── errors.go     # Typed health errors
├── checker.go    # HealthChecker interface and implementations
├── registry.go   # Thread-safe component registry
├── probes.go     # Liveness/Readiness/Startup probes
└── handlers.go   # HTTP handlers (/health, /healthz, /ready)
```

## Health Checkers

Built-in checkers:
- **QuicBaaSChecker** - Database connectivity
- **OVSChecker** - Open vSwitch status
- **DiskChecker** - Disk space monitoring
- **MemoryChecker** - Memory utilization
- **GoroutineChecker** - Goroutine count limits

## Usage

```go
// Create registry
registry := health.NewRegistry()

// Register checkers
registry.Register(health.NewDiskChecker("/var/lib", 90))
registry.Register(health.NewMemoryChecker(85))

// Check all components
result := registry.Check(ctx)
fmt.Printf("Status: %s\n", result.Status)
```

## HTTP Endpoints

- `GET /health` - Full health status (JSON)
- `GET /healthz` - Liveness probe (200/503)
- `GET /ready` - Readiness probe (200/503)

## Coverage

97%+ test coverage.
