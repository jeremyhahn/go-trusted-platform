# DHCP Unix Socket API Reference

The DHCP service does **not** currently expose an API over the Unix
socket transport. It is an in-process service configured via the
`sdn.dhcp` YAML section.

Pool and allocation state is available through the IPAM Unix socket
API — see [IPAM Unix API Reference](../ipam/api-reference-unix.md).

For the in-process Go interface see [API Reference](api-reference.md).
