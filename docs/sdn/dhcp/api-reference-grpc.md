# DHCP gRPC API Reference

The DHCP service does **not** currently expose a gRPC API. It is an
in-process service configured via the `sdn.dhcp` YAML section; there is
no DHCP service definition in the platform proto set.

Pool and allocation state is available through the IPAM gRPC API — see
[IPAM gRPC API Reference](../ipam/api-reference-grpc.md).

For the in-process Go interface see [API Reference](api-reference.md).
