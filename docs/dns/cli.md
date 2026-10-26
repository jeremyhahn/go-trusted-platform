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

The integration suite's CLI leg (`test/integration/dns/`) asserts this refusal:
every DNS operation returns the typed `ErrCLINoCommandGroup` naming #954, and the
leg fails once `platformctl --help` lists a `dns` group.

**This is a recorded omission, not planned scope.** The SPEC dns row names no
`platformctl dns` group, so the CLI is not built; the omission is recorded in
[ROADMAP.md](../../ROADMAP.md) under Later (#954). An operator lists zones, adds
records and signs zones through the [API](api.md).

---

## What to use instead, today

| Task | Reach it with |
|---|---|
| Zone and record CRUD | REST `/api/v1/dns/zones/...`, or gRPC `DNSService` |
| Sign a zone / DNSSEC status | REST or gRPC only — no QUIC, no MCP |
| Resolve a name | gRPC `Resolve`, QUIC `OpDNSResolve` (`0x29`), MCP `dns_resolve` |
| Read DNS metrics | **QUIC only** — `OpDNSGetMetrics` (`0x2C`) |
| Read DNS config | **QUIC only** — `OpDNSGetConfig` (`0x2A`) |

The two QUIC-only rows are the operational reads. No transport changes DNS
config at runtime or flushes a cache ([api.md](api.md) §2).

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
