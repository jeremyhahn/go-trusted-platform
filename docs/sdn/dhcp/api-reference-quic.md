# DHCP QUIC API Reference

The DHCP service does **not** currently expose a QUIC API. It is an
in-process service configured via the `sdn.dhcp` YAML section; no DHCP
opcodes exist in the platform QUIC wire protocol.

Pool and allocation state is available through the IPAM QUIC API — see
[IPAM QUIC API Reference](../ipam/api-reference-quic.md).

For the in-process Go interface see [API Reference](api-reference.md).
