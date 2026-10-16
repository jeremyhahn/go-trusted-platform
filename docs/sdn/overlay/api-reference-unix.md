# VXLAN Overlay Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> How to reach the overlay operations over the local socket.

## Overview

| Property | Value |
|----------|-------|
| Transport | gRPC over Unix domain socket |
| Socket | `/run/platformd.sock` |
| Service | `platform.v1.OverlayService` |
| Authentication | Unix peer credentials (SO_PEERCRED) + socket file permissions |

The Unix transport serves the **same gRPC service** as TCP port 10443 —
see [gRPC API Reference](api-reference-grpc.md) for the service
definition and messages. It is intended for local IPC; the server
authenticates callers with Unix peer credentials, and socket file
permissions gate which users/groups may connect at all.

## Client Usage

### platformctl

```bash
# Force the unix transport explicitly (also selectable via
# PLATFORMCTL_TRANSPORT=unix)
platformctl --transport unix sdn overlay status
platformctl --transport unix sdn overlay vtep list
platformctl --transport unix sdn overlay vni create --vni 1000100 --vlan 100
```

### Go (platform SDK)

Use the platform Go SDK (`sdk/go`), which knows how to dial the Unix
socket with the platform's Unix transport credentials — the same path
the CLI uses. Raw `grpc.NewClient` dials without those credentials are
not supported.

## See Also

- [gRPC API Reference](api-reference-grpc.md) — Full service definition
- [API Reference](api-reference.md) — Overview and data types
