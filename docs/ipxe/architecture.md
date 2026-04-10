# iPXE Architecture

## Component Overview

```
┌───────────────────────────────────────────────────────────────────┐
│                           PXE Server                              │
│                          (server.go)                              │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │ DHCP Server  │  │ TFTP Server  │  │    HTTP Server       │    │
│  │              │  │              │  │                      │    │
│  │ - IP assign  │  │ - iPXE.efi   │  │ - /boot.ipxe         │    │
│  │ - PXE opts   │  │ - Firmware   │  │ - /menu.ipxe         │    │
│  │ - iPXE chain │  │   caching    │  │ - /boot/{name}.ipxe  │    │
│  │              │  │              │  │ - /files/*           │    │
│  │ Port 67/udp  │  │ Port 69/udp  │  │ - /proxy/https/*     │    │
│  └──────────────┘  └──────────────┘  │                      │    │
│                                      │ Port 8080/tcp        │    │
│                                      └──────────────────────┘    │
└───────────────────────────────────────────────────────────────────┘
```

## Boot Sequence

```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│  Client  │      │   DHCP   │      │   TFTP   │      │   HTTP   │
└────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘
     │                 │                 │                 │
     │ DHCP Discover   │                 │                 │
     │────────────────>│                 │                 │
     │                 │                 │                 │
     │ DHCP Offer      │                 │                 │
     │ (IP + PXE)      │                 │                 │
     │<────────────────│                 │                 │
     │                 │                 │                 │
     │ TFTP Request: ipxe.efi           │                 │
     │─────────────────────────────────>│                 │
     │                 │                 │                 │
     │ iPXE Firmware   │                 │                 │
     │<─────────────────────────────────│                 │
     │                 │                 │                 │
     │ [iPXE starts, DHCP again]        │                 │
     │────────────────>│                 │                 │
     │                 │                 │                 │
     │ DHCP Offer      │                 │                 │
     │ (HTTP chain)    │                 │                 │
     │<────────────────│                 │                 │
     │                 │                 │                 │
     │ HTTP GET /boot.ipxe              │                 │
     │───────────────────────────────────────────────────>│
     │                 │                 │                 │
     │ chain menu.ipxe │                 │                 │
     │<───────────────────────────────────────────────────│
     │                 │                 │                 │
     │ HTTP GET /menu.ipxe              │                 │
     │───────────────────────────────────────────────────>│
     │                 │                 │                 │
     │ Boot menu script                 │                 │
     │<───────────────────────────────────────────────────│
     │                 │                 │                 │
     │ HTTP GET /boot/alpine.ipxe       │                 │
     │───────────────────────────────────────────────────>│
     │                 │                 │                 │
     │ kernel + initrd URLs             │                 │
     │<───────────────────────────────────────────────────│
     │                 │                 │                 │
     │ HTTP GET /files/vmlinuz          │                 │
     │───────────────────────────────────────────────────>│
     │                 │                 │                 │
     │ Kernel binary   │                 │                 │
     │<───────────────────────────────────────────────────│
     │                 │                 │                 │
     │ [Boot kernel]   │                 │                 │
     v                 v                 v                 v
```

## Components

### DHCP Server (`dhcp_server.go`)

Handles IP address assignment and PXE boot configuration.

**Key Features:**
- PXE client detection via DHCP option 60 (Vendor Class)
- Client architecture detection via option 93 (EFI x64, x86, BIOS)
- iPXE detection via option 175 or User-Class "iPXE"
- Raw socket support for bridged networks (`dhcp_rawconn_linux.go`)

**PXE Flow:**
1. Non-iPXE client → Returns `ipxe.efi` as boot file (TFTP)
2. iPXE client → Returns `http://server:8080/boot.ipxe` (HTTP chain)

### TFTP Server (`tftp_server.go`)

Serves iPXE firmware to boot clients.

**Key Features:**
- Downloads iPXE firmware from `boot.ipxe.org` on first run
- Caches firmware in `~/.cache/go-trusted-platform/firmware/`
- Serves `ipxe.efi` (64-bit) and `ipxe32.efi` (32-bit)

### HTTP Server (`http_server.go`)

Serves boot scripts and files.

**Endpoints:**

| Path | Purpose |
|------|---------|
| `/boot.ipxe` | Initial script, chains to menu |
| `/menu.ipxe` | Dynamic boot menu from config |
| `/boot/{name}.ipxe` | Per-entry boot script |
| `/files/*` | Local file serving |
| `/proxy/https/*` | HTTPS proxy for iPXE |
| `/health` | Health check |
| `/static/*` | Static files |

**HTTPS Proxy:**
iPXE doesn't support HTTPS. The proxy converts:
```
https://example.com/vmlinuz → http://server:8080/proxy/https/example.com/vmlinuz
```

### Server Orchestrator (`server.go`)

Coordinates all services with unified lifecycle management.

```go
server, _ := ipxe.NewServer(config, logger)
server.Start(ctx)           // Starts all services
server.WaitForReady(10*time.Second)
server.Stop()               // Graceful shutdown
```

## Test Environment Integration

The `testenv.go` provides isolated network setup for testing:

```
┌───────────────────────────────────────────────────────────┐
│                      Host System                          │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                Bridge: pxe-br                       │  │
│  │                IP: 10.99.99.1/24                    │  │
│  │                                                     │  │
│  │  ┌────────────────┐      ┌────────────────────┐    │  │
│  │  │  PXE Server    │      │  TAP: tap-pxe      │    │  │
│  │  │  DHCP/TFTP/    │      │                    │    │  │
│  │  │  HTTP          │      │  -> QEMU VM        │    │  │
│  │  └────────────────┘      └────────────────────┘    │  │
│  │                                                     │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                               │
│                     NAT (iptables)                        │
│                           │                               │
│                       Internet                            │
└───────────────────────────────────────────────────────────┘
```

**Network Configuration:**
- Bridge: `pxe-br` (10.99.99.1)
- TAP: `tap-pxe` (attached to bridge)
- DHCP Range: 10.99.99.100 - 10.99.99.200
- NAT via iptables MASQUERADE

## File Layout

```
pkg/ipxe/
├── config.go              # Configuration types
├── errors.go              # Typed errors
├── server.go              # Orchestrator
├── dhcp_server.go         # DHCP with PXE
├── dhcp_rawconn_linux.go  # Raw sockets (Linux)
├── dhcp_rawconn_stub.go   # Non-Linux stub
├── tftp_server.go         # TFTP firmware server
├── http_server.go         # HTTP boot scripts
├── testenv.go             # Test environment
├── iso.go                 # ISO extraction
└── *_test.go              # Tests
```
