# TPM API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> Index of the TPM service's transports and RPCs. The cross-transport
> contract is [api.md](api.md).

The TPM service exposes physical Trusted Platform Module operations via multiple protocols for maximum interoperability.

## Supported Protocols

| Protocol | Transport | Port/Path | Use Case |
|----------|-----------|-----------|----------|
| [REST](api-reference-rest.md) | HTTPS | 8443 | Web clients, external systems |
| [gRPC](api-reference-grpc.md) | TCP | 10443 | High-performance service-to-service |
| [QUIC](api-reference-quic.md) | UDP | 9444 | Low-latency, mobile clients |
| [MCP](api-reference-mcp.md) | stdio/HTTPS | 9445 | AI/LLM integration |
| [Unix Socket](api-reference-unix.md) | Unix | /run/platformd.sock | Local IPC, CLI |

## RPCs

`platform.v1.TPMService` (`pkg/api/grpc/proto/tpm.proto`) is the one service
every transport carries. Its request and response messages are defined in the
proto; [api.md](api.md) gives each RPC's row on every transport.

| Group | RPCs | [api.md](api.md) |
|-------|------|------------------|
| Device and lifecycle | `Info`, `GetCapabilities`, `GetPlatformAttributes`, `Provision`, `Clear` | §3 |
| Endorsement key | `CreateEK`, `GetEK`, `DeleteEK`, `GetEKCertificate`, `ImportEKCertificate` | §4 |
| Storage root key | `CreateSRK`, `GetSRK`, `DeleteSRK` | §4 |
| Attestation key | `CreateAK`, `GetAK`, `DeleteAK` (refused with `FailedPrecondition`: the IAK is not evicted) | §4 |
| Sealing | `Seal`, `Unseal` (a `Seal` under a password; naming PCRs is refused with `FailedPrecondition` until go-quicbaas #1171) | §5 |
| Attestation and PCRs | `Quote`, `VerifyQuote`, `Certify`, `GetEventLog`, `GetPCRs`, `ExtendPCR` | §5 |
| Credential activation | `MakeCredential`, `ActivateCredential` | §7 |
| NVRAM | `DefineNVRAM`, `WriteNVRAM`, `ReadNVRAM`, `UndefineNVRAM` | §6 |
| Entropy | `GetRandom` | §5 |

Device identity (IDevID, IAK, LDevID) is a separate service,
`IDevIDService` ([api.md](api.md) §8). Scopes are §9; status and error
mapping is §10.

## Connecting

### Unix socket (local IPC)

```go
conn, err := grpc.NewClient(
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewTPMServiceClient(conn)
```

### gRPC (TCP)

```go
creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
if err != nil {
    return err
}

conn, err := grpc.NewClient("localhost:10443", grpc.WithTransportCredentials(creds))
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewTPMServiceClient(conn)
```

Under mTLS the listener requires a client certificate on every TPM RPC
(`pkg/api/daemon/client_cert_gate.go`); add it to the TLS config.

### REST (HTTPS)

```bash
curl --cacert ca.crt --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/tpm/info
```

### QUIC and MCP

See [api-reference-quic.md](api-reference-quic.md) and
[api-reference-mcp.md](api-reference-mcp.md).
