# DHCP REST API Reference

The DHCP service does **not** currently expose a REST API. It is an
in-process service configured via the `sdn.dhcp` YAML section; there
are no DHCP HTTP endpoints in the platform REST surface.

Pool and allocation state is available through the IPAM REST API — see
[IPAM REST API Reference](../ipam/api-reference-rest.md).

For the in-process Go interface see [API Reference](api-reference.md).
