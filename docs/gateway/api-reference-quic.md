# Gateway QUIC API Reference

Gateway QUIC commands use category `0x2F`.

| Opcode | Name | Description |
|---|---|---|
| `0x01` | `OpGatewayStatus` | Gateway node status. |
| `0x02` | `OpGatewaySetMode` | Deprecated compatibility mode setter. |
| `0x15` | `OpGatewaySnapshot` | Read one gateway snapshot. |
| `0x16` | `OpGatewayListSnapshots` | List reported gateway snapshots. |
| `0x17` | `OpGatewayAdmittedVTEP` | Read one admitted overlay VTEP by IP address. |
| `0x18` | `OpGatewayListAdmittedVTEPs` | List admitted overlay VTEPs. |

The snapshot payload includes an `overlay` object when gatewayd runs the overlay
service. It includes local VTEP metadata, admitted VTEPs and ND counters for
punted, answered, meter-dropped, queue-dropped and fell-through packets.
