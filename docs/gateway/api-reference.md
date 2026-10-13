# Gateway API Reference

The gateway API is a platform-owned Tier 1 surface. The canonical transport
matrix and behavior notes live in [api.md](api.md); this reference links the
protocol-specific forms.

| Protocol | Reference |
|---|---|
| REST | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | [api-reference-quic.md](api-reference-quic.md) |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix socket | [api-reference-unix.md](api-reference-unix.md) |

Gateway overlay status is reported in the gateway snapshot. The overlay section
contains local VTEP metadata, admitted VTEPs, and ND counters for punted,
answered, meter-dropped, queue-dropped and fell-through packets. Admitted VTEP
read/list calls use the same service layer on every transport.
