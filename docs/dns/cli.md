# DNS — CLI

> **Status: NORMATIVE** · Scope: DNS verbs in `platformctl` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.

---

## No CLI surface

**There is no `platformctl dns` command group.** `pkg/cli/commands/` has no
`dns` directory, and `pkg/cli/commands/root.go` registers no DNS group among its
44 top-level commands (verified 2026-10-11; [`docs/daemon/cli.md`](../daemon/cli.md) §3). Nothing else in the CLI carries DNS
verbs either.

Authoritative DNS is reachable only through the SDK, REST, gRPC, Unix, QUIC and
MCP. [api.md](api.md) has the full matrix.

**This is a gap, not a design decision.** DNS is a Tier 1 platform capability
that an operator cannot exercise from a shell: no way to list zones, add a
record, sign a zone or flush the cache without writing a client. It is raised in
the migration report as an owner question — whether to build `platformctl dns`
or to record the omission deliberately.

### A prior document described this CLI as if it existed

The deleted cli-reference.md was a full reference for a
`platformctl dns` tree — `zone`, `record`, `dnssec`, `dane`, `update`, `delete`,
`server` subcommand categories, with flags and examples. **None of it exists.**
That file has been fenced with an ARCHIVE banner rather than deleted, because it
is a useful specification if the CLI is ever built. Do not treat it as a
description of the product.

---

## What to use instead, today

| Task | Reach it with |
|---|---|
| Zone and record CRUD | REST `/api/v1/dns/zones/...`, or gRPC `DNSService` |
| Sign a zone / DNSSEC status | REST or gRPC only — no QUIC, no MCP |
| Resolve a name | gRPC `Resolve`, QUIC `OpDNSResolve` (`0x29`), MCP `dns_resolve` |
| Flush the cache | **QUIC only** — `OpDNSFlushCache` (`0x2D`) |
| Read DNS metrics | **QUIC only** — `OpDNSGetMetrics` (`0x2C`) |
| Read or change DNS config | **QUIC only** — `OpDNSGetConfig` (`0x2A`), `OpDNSUpdateConfig` (`0x2B`) |

The four QUIC-only rows are the operational verbs. An operator without a QUIC
client cannot flush the DNS cache.

---

## Adjacent CLI that touches DNS

DNS-adjacent behaviour does appear in other command groups:

- **ACME DNS-01 challenges** — `platformctl acme` ([`docs/ca/`](../ca/)) uses
  DNS records to answer challenges; see [acme-integration.md](acme-integration.md).
- **DANE** — `platformctl tpm` / trust verbs consume TLSA records published by
  this feature; see [dane.md](dane.md).

Neither is a DNS management surface.

---

## Parity gap

`conventions/feature-docs.md` §4 requires every `cli.md` verb to have a
`CommandDefinition` in the integration parity suite. There are no verbs here,
and **no `CommandDefinition` type exists in this repository at all** (grepped
2026-08-18) — so the requirement is unmet repo-wide as well as vacuous here.
