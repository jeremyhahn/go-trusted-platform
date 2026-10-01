# SDN QUIC API Reference

Endpoint: UDP port 9444, mTLS required.

Requests and responses are msgpack-encoded frames; msgpack keys follow
the Go field names declared in the QUIC handler types. Opcodes are
defined in `pkg/api/quic/protocol.go`.

## SDN Opcodes

| Opcode | Operation | Description |
|--------|-----------|-------------|
| `0x40` | SDNGetPortState | Get port admin state |
| `0x41` | SDNSetPortState | Set port admin state |
| `0x42` | SDNListPorts | List ports on a bridge |
| `0x43` | SDNGetFlow | Get a flow |
| `0x44` | SDNAddFlow | Add a flow rule |
| `0x45` | SDNDeleteFlow | Delete a flow rule |
| `0x46` | SDNListFlows | List flows |
| `0x47` | SDNApplyPolicy | Apply a policy |
| `0x48` | SDNGetPolicy | Get a policy |
| `0x49` | SDNListPolicies | List policies |
| `0x4A` | SDNGetBridge | Get a bridge |
| `0x4B` | SDNListBridges | List bridges |
| `0x4C` | SDNGetMetrics | Get SDN metrics |
| `0x4D` | SDNSetVLAN | Set a VLAN |
| `0x4E` | SDNGetVLAN | Get a VLAN |
| `0x4F` | SDNGetPort | Get a port |
| `0xB0` | SDNCreateBridge | Create a bridge |
| `0xB1` | SDNDeleteBridge | Delete a bridge |
| `0xB2` | SDNCreatePort | Create a port |
| `0xB3` | SDNDeletePort | Delete a port |
| `0xB4` | SDNDeletePolicy | Delete a policy |

Related SDN category opcodes: the overlay service uses category opcode
`0x2E` with its own sub-opcodes (see
[overlay/api-reference-quic.md](overlay/api-reference-quic.md)); the
gateway and IPAM surfaces have their own opcode assignments in
`pkg/api/quic/gateway_handlers.go`. The zone operations are gateway
category (`0x2F`) sub-opcodes `0x10` list, `0x11` create, `0x12` update and
`0x13` delete; `0x14` (the retired assign operation) is never reused. Their
codec bodies carry the whole zone schema (`offset`, `port_classes`,
`allow_to`, `services`, `privileged_access`, …) and list/create/update
responses carry `numbering` when the node has an `sdn.environment`.

## Client Usage

The platformctl CLI exercises the QUIC transport with
`--transport quic`:

```bash
platformctl --transport quic sdn bridge list
platformctl --transport quic sdn flow list --bridge br0
```

## See Also

- [API Reference](api-reference.md) — Overview and data types
- [gRPC API Reference](api-reference-grpc.md)
