# Platform Tenancy — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> What an operator does with tenants, in the order they do it. Internals are in
> [engineering.md](engineering.md).

---

## What a tenant is here

Not an account. A tenant on this platform is **four allocations plus a quota**:

| Piece | What it isolates |
|---|---|
| A **VLAN** | Layer 2 traffic |
| A **bridge** | The tenant's ports |
| A **keyspace** | The tenant's data in the store |
| A **DEK** | The tenant's data at rest |
| A **quota** | How much the tenant may consume |

That is why creating a tenant can fail in four different ways, and why the
errors name which allocation failed.

**Users, groups and roles are a different thing.** IAM has its own tenant
scoping under `/api/v1/iam/tenants/...`. Creating something there does not
allocate a VLAN or a DEK. If you want a platform tenant, use
`platformctl tenant create`.

---

## Prerequisites

1. A running control plane with the tenant service enabled — otherwise every
   call returns 503.
2. **A VLAN range configured** for tenant allocation. Outside it, allocation is
   refused with an invalid-range error rather than colliding.
3. SDN configured, since a tenant gets a real bridge on a real datapath
   ([`docs/sdn/`](../sdn/)).

---

## Creating and running a tenant

```bash
platformctl tenant create --name tenant-a --display-name "Tenant A"
platformctl tenant list
platformctl tenant show tenant-a
```

Confirm all four allocations landed:

```bash
platformctl tenant vlan tenant-a       # the VLAN
platformctl tenant bridge tenant-a     # the bridge
platformctl tenant usage tenant-a      # quota accounting
# DEK status is API-only: GET /api/v1/tenants/{id}/dek
```

CLI verbs take the tenant **name**. The API is keyed by **ID**, with a separate
`by-name` lookup. That difference will bite when you script against both.

---

## The lifecycle, and the one-way door

```
created ──> active ──> suspended
              │   ↖________│
              │
              └──> deleting ──> deleted
```

- **Suspend and resume are reversible.** Use suspension for anything you might
  undo — non-payment, an investigation, a maintenance freeze.
- **`deleting` cannot be cancelled**, and **`deleted` is terminal**. No
  transition leaves it. A deleted tenant is not restored; a new one is created,
  with a new VLAN, bridge, keyspace and DEK.
- **Repeating an operation is safe.** Suspending an already-suspended tenant
  succeeds rather than erroring, so retries and reconciliation loops behave.

```bash
platformctl tenant suspend tenant-a
platformctl tenant resume tenant-a
platformctl tenant delete tenant-a --force   # no undo
```

---

## Quotas

```bash
platformctl tenant quotas get tenant-a
platformctl tenant quotas set tenant-a --max-vms 20 --max-vcpus 80 --max-memory-gb 256
```

**Only the flags you pass are changed.** An omitted flag leaves that limit
alone. This is deliberate: `0` is a real limit meaning "no capacity", so
omitting a flag cannot be treated as setting it to zero.

To set a limit to zero — genuinely blocking a resource — pass it explicitly:

```bash
platformctl tenant quotas set tenant-a --max-vms 0
```

**Check the units.** `--max-memory-gb` is gigabytes at the CLI, and the stored
field is in megabytes. Several other flags (`--max-bridges`, `--max-ports`,
`--max-bandwidth-mbps`, `--max-volumes-gb`, `--max-snapshots`) do not correspond
to fields in the compute quota structure. Verify a value took effect with
`quotas get` rather than assuming.

Before provisioning something large, ask whether it fits rather than finding out
by failure — that is what the quota-check API is for
(`POST /api/v1/tenants/{id}/quota-check`).

---

## Per-tenant barriers

A barrier is a cryptographic seal over the tenant's data. Sealed means the data
is inaccessible until unsealed.

```bash
platformctl tenant barrier init tenant-a
platformctl tenant barrier status tenant-a
platformctl tenant barrier seal tenant-a
platformctl tenant barrier unseal tenant-a --key-hex <key>
```

Two things to get right:

**Do not type unseal keys into an interactive shell.** They land in shell
history and in the process table. Use a mechanism that does not.

**Barriers are not available in every configuration.** A 501 / "barrier not
supported" is a capability answer, not a fault. Check `barrier status` before
building a procedure around sealing.

---

## Rotating a tenant's DEK

API-only:

```bash
curl -s -X POST https://platform.example.com/api/v1/tenants/<id>/dek/rotate
curl -s        https://platform.example.com/api/v1/tenants/<id>/dek
```

**Rotation rewraps the key; it does not re-encrypt the tenant's data.** That is
why rotation is fast and why it does not need a maintenance window.

---

## Troubleshooting

**Tenant creation fails and names the VLAN.**
Either the configured VLAN range is exhausted, or the range itself is invalid.
Range validity is checked before allocation, so the two errors are distinct.

**Tenant creation fails and names the bridge or the DEK.**
One of the four allocations did not complete. The tenant is partially
constructed; check `vlan`, `bridge` and DEK status to see how far it got before
retrying.

**An operation returns a conflict on a tenant that looks fine.**
The tenant is in a state that does not permit it — `deleting` accepts nothing
but completion, and `deleted` accepts nothing at all.

**Everything is refused with a resource error.**
Quota exceeded, or a hard resource ceiling. `usage` shows which.

**A quota you set had no effect.**
Check the unit and confirm with `quotas get`. `--max-memory-gb` is gigabytes at
the CLI and megabytes in the stored field, and several CLI quota flags have no
corresponding stored field.

**Everything returns 503.**
The tenant service is not wired into the daemon.

---

## One thing to be aware of

Tenant operations — including **init, seal and unseal of a per-tenant barrier** —
currently require only a validated token, not a specific scope, on gRPC, Unix,
MCP and embedded. Barrier operations are key-custody operations. Until that is
resolved, treat any credential that can reach the tenant API as a
tenancy-administrator credential. It is recorded in [api.md](api.md) §7 and
raised for the owner.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — how the four allocations compose
- [`docs/sdn/`](../sdn/) · [`docs/compute/`](../compute/) · [`docs/iam/`](../iam/)
