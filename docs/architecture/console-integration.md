# Native Serial Console Integration

## Overview

Built-in serial console capability for go-trusted-platform, enabling direct console access to managed servers without BMC/IPMI dependency. Provides bootstrap debugging, operational monitoring, and a native web-based terminal.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Console Service                        │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐            │
│  │ SOL      │  │ Serial   │  │ SSH       │            │
│  │ Client   │  │ Port     │  │ Console   │            │
│  │ (IPMI)   │  │ (local)  │  │ (remote)  │            │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘            │
│       │             │              │                    │
│       └─────────────┼──────────────┘                    │
│                     │                                   │
│              ┌──────▼──────┐                            │
│              │  Console    │                            │
│              │  Mux        │───── Recorder (log)        │
│              │             │───── Pattern Matcher       │
│              └──────┬──────┘      (error detection)     │
│                     │                                   │
│       ┌─────────────┼──────────────┐                    │
│       │             │              │                    │
│  ┌────▼─────┐ ┌─────▼────┐ ┌──────▼─────┐            │
│  │ CLI      │ │ WebSocket│ │ Bootstrap  │            │
│  │ Terminal │ │ Terminal │ │ Monitor    │            │
│  └──────────┘ └──────────┘ └────────────┘            │
└─────────────────────────────────────────────────────────┘
```

## Console Backend Implementations

### SOL Client (IPMI Serial Over LAN)

Pure Go IPMI SOL client for remote serial console access via BMC.

- Connects to BMC IPMI port (623/UDP)
- RAKP authentication (reuses existing `pkg/bmc/rmcp.go`)
- SOL payload activation/deactivation
- Bidirectional character stream
- Keepalive management

### Serial Port (Local)

Direct serial port access for local console on the same machine.

- Opens `/dev/ttyS0` (or configured port)
- Configurable baud rate, parity, stop bits
- Used by platform-initrd during boot for console output
- Used by platformd for local management console

### SSH Console

SSH-based remote console using the platform's SSH server.

- Reuses existing SSH infrastructure
- PTY allocation for interactive terminal
- Channel multiplexing for concurrent sessions

## Console Multiplexer

Fans out console I/O to multiple consumers:

- **Recorder**: Writes all console output to timestamped log files
- **Pattern Matcher**: Watches for configurable patterns (kernel panic, LUKS failure, login prompt) and triggers callbacks
- **Terminal**: Interactive read/write for CLI or web UI
- **Bootstrap Monitor**: Tracks install/boot progress by parsing console output

## CLI Commands

```bash
# Attach to server console via IPMI SOL
platformctl console attach --bmc 198.18.1.103

# Watch console output (read-only)
platformctl console watch --bmc 198.18.1.103

# View captured console log
platformctl console log --bmc 198.18.1.103

# Monitor bootstrap progress
platformctl bootstrap monitor --bmc 198.18.1.103
```

## Bootstrap Integration

The bootstrap orchestrator uses the console to:

1. **Monitor install progress**: Parse console output for `[autoinstall]` messages
2. **Detect completion**: Watch for `poweroff` or `reboot` patterns
3. **Detect errors**: Watch for `kernel panic`, `LUKS`, `error`, `failed` patterns
4. **Capture logs**: Record full console output for debugging

```go
type BootstrapConsole struct {
    sol      *console.SOLClient
    recorder *console.Recorder
    matcher  *console.PatternMatcher
}

// WaitForPattern blocks until a pattern matches or timeout
func (bc *BootstrapConsole) WaitForPattern(ctx context.Context, pattern string) error

// WaitForPowerOff monitors console for shutdown indicators
func (bc *BootstrapConsole) WaitForPowerOff(ctx context.Context) error
```

## Web UI Integration

WebSocket-based terminal component in the React admin UI:

- xterm.js terminal emulator in the browser
- WebSocket connection to platformd REST API
- Live console view per managed server
- Console log history with search
- Multiple concurrent console sessions

### API Endpoints

```
GET  /api/v1/console/{hostname}/attach  → WebSocket upgrade
GET  /api/v1/console/{hostname}/log     → console log (JSON lines)
POST /api/v1/console/{hostname}/send    → send input to console
```

## Configuration

```yaml
console:
  # Serial port for local console
  serial:
    enabled: true
    port: /dev/ttyS0
    baud: 115200
    
  # SOL configuration for remote console
  sol:
    enabled: true
    # BMC credentials come from the device profile
    
  # Console recording
  recorder:
    enabled: true
    log-dir: /var/log/trusted-platform/console
    max-size: 100MB
    rotate: 5
    
  # Pattern matching for automated monitoring
  patterns:
    install-complete: "Installation completed successfully"
    boot-complete: "platformd is running"
    error: "kernel panic|LUKS.*failed|ERROR.*fatal"
    login-prompt: "login:"
```

## Implementation Order

1. SOL Client (pure Go IPMI SOL) — enables remote console without ipmitool
2. Console Recorder — captures output to files
3. Pattern Matcher — automated progress/error detection
4. CLI commands (attach, watch, log)
5. Bootstrap orchestrator integration
6. Web UI terminal (xterm.js + WebSocket)
