# Platform Tenancy — CLI

> **Status: NORMATIVE** · Scope: `platformctl tenant` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/tenant/` on 2026-08-18.

---

## 1. Command group

```
platformctl tenant    Tenant management operations
```

Eighteen verbs across the group, `quotas` and `barrier`.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` (`unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`) |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

Every verb needs a reachable daemon. `--transport embedded` runs in-process.

---

## 2. Lifecycle verbs

| Verb | Positional | Flags |
|---|---|---|
| `create` | — | `--name` (required, unique), `--display-name` |
| `list` | — | — |
| `show` | `<tenant-name>` | — |
| `suspend` | `<tenant-name>` | — |
| `resume` | `<tenant-name>` | — |
| `delete` | `<tenant-name>` | `--force` (skip the confirmation prompt) |

**Verbs take a tenant *name*, not an ID.** The REST and gRPC surfaces are
ID-keyed with a separate `by-name` lookup; the CLI is name-keyed throughout.

```bash
platformctl tenant create --name tenant-a --display-name "Tenant A"
platformctl tenant list --output json
platformctl tenant show tenant-a
platformctl tenant suspend tenant-a
platformctl tenant resume tenant-a
platformctl tenant delete tenant-a --force
```

**Suspension is reversible; deletion is not.** The lifecycle is
`created → active → suspended ⇄ active → deleting → deleted`, and `deleted` is
terminal: no transition leaves it, so a deleted tenant is replaced rather than
restored. `--force` only skips the prompt; it does not make deletion any more
recoverable.

Re-running `suspend` on a suspended tenant succeeds — same-state transitions are
allowed so retried calls do not fail.

---

## 3. `platformctl tenant quotas`

| Verb | Positional |
|---|---|
| `get` | `<tenant-name>` |
| `set` | `<tenant-name>` |

**`set` flags** — all `int64`, all default `0`:

| Flag | Meaning |
|---|---|
| `--max-vms` | Maximum number of VMs |
| `--max-containers` | Maximum number of containers |
| `--max-vcpus` | Maximum number of vCPUs |
| `--max-memory-gb` | Maximum memory in GB |
| `--max-bridges` | Maximum number of bridges |
| `--max-ports` | Maximum number of network ports |
| `--max-bandwidth-mbps` | Maximum bandwidth in Mbps |
| `--max-volumes-gb` | Maximum volume storage in GB |
| `--max-snapshots` | Maximum number of snapshots |

**Updates are partial by design.** Each flag is applied only if
`cmd.Flags().Changed(...)` reports it was given, so an omitted flag leaves the
existing limit alone. That matters because **`0` is a real value meaning "no
capacity"** — without the `Changed` check, omitting a flag would zero the limit.

**Two unit hazards.** The CLI flag is `--max-memory-gb` while the underlying
field is `MaxMemoryMB` — **megabytes**. And `--max-bridges`, `--max-ports`,
`--max-bandwidth-mbps`, `--max-volumes-gb` and `--max-snapshots` have no
counterpart field in `ComputeQuota`, which carries only VMs, containers, vCPUs,
memory and disk. Confirm what a value lands in before setting it.

```bash
platformctl tenant quotas get tenant-a
platformctl tenant quotas set tenant-a --max-vms 20 --max-vcpus 80 --max-memory-gb 256
```

---

## 4. Inspection verbs

| Verb | Positional | Shows |
|---|---|---|
| `usage` | `<tenant-name>` | Resource usage against limits |

```bash
platformctl tenant usage tenant-a
```

The former `vlan` and `bridge` verbs were removed with the per-tenant VLAN
range and OVS bridge (#708): a tenant has neither. DEK status is API-only from
the CLI's point of view (§6).

---

## 5. `platformctl tenant barrier`

Per-tenant cryptographic barrier lifecycle.

| Verb | Positional | Flags |
|---|---|---|
| `init` | `<tenant-name>` | — |
| `unseal` | `<tenant-name>` | `--key-hex`, `--key-base64` |
| `seal` | `<tenant-name>` | — |
| `status` | `<tenant-name>` | — |

```bash
platformctl tenant barrier init tenant-a
platformctl tenant barrier status tenant-a
platformctl tenant barrier seal tenant-a
```

**Do not type an unseal key as a command-line argument in an interactive
shell.** `--key-hex` and `--key-base64` take the key material directly, and a
shell with history recording will record it. Prefer a mechanism that does not
land the key in `~/.*_history` or in the process table.

**Per-tenant barriers may not be supported** in a given configuration — the
error is `ErrBarrierNotSupported`, mapped to 501. That is a capability answer,
not a failure.

---

## 6. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Rotate the tenant DEK | REST `POST /api/v1/tenants/{id}/dek/rotate`, gRPC `RotateTenantDEK`, MCP `tenant_rotate_dek` |
| Tenant DEK status | REST `GET /api/v1/tenants/{id}/dek`, MCP `tenant_get_dek_status` |
| Check quota for a prospective allocation | REST `POST .../quota-check`, gRPC `CheckQuota` |
| Sync tenants | REST `POST /api/v1/tenants/sync`, gRPC `Sync` |
| Get tenant by name over the API | gRPC `GetTenantByName`, REST `/by-name/{name}` |

---

## 7. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
