# Security Package

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [cli.md](cli.md), [api.md](api.md) and [user.md](user.md); architecture.md §8 lists what is stale here. `pkg/security/audit` does not exist; `pkg/security` holds only `ratelimit` and `validation`.

Security utilities for rate limiting, audit logging, and input validation.

## Overview

The security package provides production-grade security components:

- **Rate Limiting** - Token bucket and sliding window limiters
- **Audit Logging** - Async security event logging
- **Input Validation** - XSS, SQL injection, path traversal prevention

See also [Protected Memory](protected-memory.md) for `MemoryEnclave`, the
platform primitive that holds keys, passwords, tokens and shares in locked,
zeroized memory.

## Package Structure

```
pkg/security/
├── ratelimit/
│   ├── types.go         # Limiter interface
│   ├── token_bucket.go  # Lock-free token bucket
│   └── sliding_window.go # Sliding window limiter
├── audit/
│   ├── types.go         # AuditEvent, AuditLogger interface
│   ├── logger.go        # Async buffered logger
│   └── middleware.go    # HTTP/gRPC middleware
└── validation/
    ├── sanitize.go      # Path traversal, XSS stripping
    └── validators.go    # Email, URL, IP, UUID validators
```

## Rate Limiting

```go
// Token bucket (lock-free)
limiter := ratelimit.NewTokenBucket(1000, 100) // 1000/sec, burst 100
if !limiter.Allow("user-123") {
    return ErrRateLimited
}

// Sliding window
limiter := ratelimit.NewSlidingWindow(100, time.Minute)
```

## Audit Logging

```go
logger := audit.NewLogger(
    audit.WithBufferSize(1000),
    audit.WithFlushInterval(time.Second),
)

logger.Log(audit.NewEvent().
    Action("user.login").
    UserID("user-123").
    Success(true).
    Build())
```

## Input Validation

```go
// Sanitize paths
safe := validation.SanitizePath(input)

// Strip XSS
clean := validation.StripXSS(html)

// Validate inputs
if err := validation.ValidateEmail(email); err != nil {
    return err
}
```

## Coverage

- Rate limiting: 82%+
- Audit logging: 69%+
- Validation: 86%+
