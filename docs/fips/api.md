# FIPS Mode — API

> **Status: NORMATIVE** · Scope: API surface of FIPS mode · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

FIPS mode has no endpoint, RPC or MCP tool on any transport. It is chosen at
build, boot and install time ([cli.md](cli.md)). Its refusals come back through
the existing feature APIs as each feature's typed errors
([engineering.md](engineering.md) §2–§4).
