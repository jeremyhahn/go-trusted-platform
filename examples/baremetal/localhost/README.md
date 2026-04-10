# Trusted Platform Localhost Example

This example demonstrates a complete Trusted Platform deployment with server and client running on localhost using the TPM simulator.

## Features Demonstrated

- **TPM-based attestation** - Hardware security using TPM simulator
- **Automatic enrollment** - Zero-touch client provisioning via ACME
- **Certificate management** - Full PKI with CA and automatic issuance
- **Secure communication** - mTLS after enrollment

## Quick Start

Just three commands to see it in action:

```bash
# 1. Setup everything (build, configure, initialize)
make all

# 2. Terminal 1: Start the server
make run-server

# 3. Terminal 2: Start the client (auto-enrolls!)
make run-client
```

The client automatically:
1. Generates TPM-backed keys
2. Creates enrollment request
3. Completes ACME challenge
4. Receives signed certificates
5. Starts HTTPS service on port 9443

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│     Server      │         │     Client      │
│                 │         │                 │
│  - CA Service   │ <────── │  - ACME Client  │
│  - ACME Server  │  ACME   │  - TPM Keys     │
│  - DNS Server   │         │  - Web Service  │
│  - Web Service  │         │                 │
│                 │         │                 │
│  Port: 8443     │         │  Ports: 8081,   │
│                 │         │         9443    │
└─────────────────┘         └─────────────────┘
        │                             │
        └──────── TPM Simulator ──────┘
```

## Key Features Demonstrated

1. **TPM Simulator**: Both server and client use the TPM simulator for key generation and storage
2. **Dynamic Hostname**: Uses your system's hostname dynamically (e.g., `myhostname.local`)
3. **Auto-Enrollment**: Client automatically enrolls on startup using the `enroll-01` ACME challenge
4. **Certificate Chain**: Server runs a CA that issues certificates to enrolled clients
5. **Secure Communication**: After enrollment, client has TLS certificates for secure communication

## Available Commands

```bash
# View all available targets
make help

# Check status of both server and client
make status

# Test TPM attestation
make test-attestation

# View logs
make logs

# Clean everything
make clean
```

## How It Works

1. **Single Makefile** - Everything is managed from one Makefile
2. **Auto-generated** - Server and client directories are created on demand
3. **Dynamic config** - Uses your hostname automatically (e.g., `myhostname.local`)
4. **Zero manual steps** - Client enrolls automatically on startup

## Available Commands

```bash
make help           # Show all available commands
make status         # Check server and client status  
make logs           # View recent logs
make test-server-ca # Test server CA functionality
make test-client-tpm # Test client TPM functionality
make clean          # Remove all generated files
```

## Configuration

Default settings (override with environment variables):
```bash
PASSWORD=mypass SERVER_PORT=9443 CLIENT_PORT=8082 make all
```

- `PASSWORD` - TPM simulator password (default: test)
- `SERVER_PORT` - Server HTTPS port (default: 8443)
- `CLIENT_PORT` - Client HTTP port (default: 8081)
- `CLIENT_TLS_PORT` - Client HTTPS port (default: 9443)

## Project Structure

The Makefile generates this structure:
```
localhost/
├── Makefile          # This file - manages everything
├── README.md         # You are here
├── server/           # Generated on 'make all'
│   ├── config.yaml
│   ├── public_html/
│   └── trusted-data/
└── client/           # Generated on 'make all'
    ├── config.yaml
    ├── public_html/
    └── trusted-data/
```

## Troubleshooting

- **Ports in use**: Ensure 8443, 8081, and 9443 are available
- **Build errors**: Run `cd ../../.. && make build` first
- **TPM errors**: Simulator requires no special permissions
- **Enrollment fails**: Check server is running before client

## Next Steps

After enrollment completes:
- Server API: https://localhost:8443/api/v1/status
- Client API: https://localhost:9443/api/v1/status
- View certificates: `make test-server-ca`
- Test attestation: `make test-client-tpm`