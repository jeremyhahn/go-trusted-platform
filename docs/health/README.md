# Health Check Framework

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `pkg/health` component registry: status vocabulary, checker interface and usage.

Component-health registry for platform services, layered on the shared
quicbaas SDK health-probe framework.

## Overview

The platform status vocabulary is the shared quicbaas SDK
`HealthCheckStatus` (`healthy` / `degraded` / `unhealthy`), re-exported as
`health.HealthStatus`, plus a platform-local `StatusUnknown` for checks
that time out before reporting. The Kubernetes-style probe primitives
(liveness / readiness / startup) live upstream in the quicbaas SDK
(`quicbaas.HealthChecker`); this package adds only the platform
extensions the shared framework does not provide:

- **Registry** — parallel, timeout-bounded checks across all registered
  components, per-component queries, duplicate-name rejection, and
  aggregate counts consumed by the platform gRPC/REST health APIs.
- **ComponentHealth / SystemHealth** — Details-bearing results with the
  four-state status (including `unknown` for timed-out checks).

## Package Structure

```
pkg/health/
├── types.go      # HealthStatus (SDK alias + StatusUnknown), ComponentHealth, SystemHealth
├── errors.go     # Typed registry errors
├── checker.go    # HealthChecker interface
├── probe.go      # Liveness, readiness and aggregate verdicts over the registry
└── registry.go   # Thread-safe component registry
```

## Usage

Components implement `health.HealthChecker` (`Name()` +
`Check(ctx) ComponentHealth`) and register with the daemon's registry:

```go
registry := health.NewRegistry()
if err := registry.Register(checker); err != nil {
    return err
}

// Check all components in parallel (per-check timeout applies)
result := registry.Check(ctx)
fmt.Printf("Status: %s\n", result.Status)
```

The daemon exposes the registry through the platform multi-protocol
health APIs (gRPC `GetHealth`, daemon REST `/api/v1/health`, webservice
REST `/api/v1/platform/health`, QUIC, MCP) and the root `/health`,
`/health/live` and `/health/ready` probes.

## Coverage

98%+ test coverage.
