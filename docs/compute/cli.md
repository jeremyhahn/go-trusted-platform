# Compute — CLI

> **Status: NORMATIVE** · Scope: `platformctl compute`, `platformctl container` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/compute/` and `pkg/cli/commands/container/` on
> 2026-08-18.

---

## 1. Two command groups

```
platformctl compute      Virtual machine operations
platformctl container    Container orchestration operations
```

**The VM group is called `compute`, not `vm`.** Its `Short` string is "Virtual
machine operations" — the group name and what it does do not match, which is
the first thing that costs someone a minute.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

**Short-flag shadowing.** `compute list` and `container list` bind `-f` to
`--filter`, and `compute delete` and `container remove` bind `-f` to `--force`.
`container remove --volumes` has no short form: `-v` is the global
`--verbose`. **Use long forms in scripts.**

---

## 2. `platformctl compute`

| Verb | Positional | Purpose |
|---|---|---|
| `create` | — | Create a new virtual machine |
| `list` | — | List virtual machines |
| `get` | `<vm-id>` | VM details |
| `start` | `<vm-id>` | Start a VM |
| `stop` | `<vm-id>` | Stop a running VM |
| `delete` | `<vm-id>` | Delete a VM |
| `migrate` | `<vm-id> --destination <host:port>` | Migrate to another host |

### `compute create`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--name` | `-n` | string | | VM name (**required**) |
| `--firmware` | | string | `uefi` | `bios`, `uefi`, `uefi-secure-boot` |
| `--secure-boot` | | bool | `false` | Enable UEFI Secure Boot |
| `--tpm` | | bool | `false` | Enable a virtual TPM (vTPM) |
| `--boot-device` | | string | `disk` | `disk`, `cdrom`, `network` |
| `--network-bridge` | | string | | Network bridge name |
| `--label` | `-l` | string array | | Labels (`key=value`), repeatable |
| `--start` | | bool | `false` | Start immediately after creation |

**`--firmware` defaults to `uefi`, and `--secure-boot` does not.** Secure Boot
needs UEFI firmware — `--firmware bios --secure-boot` is a contradiction. Use
`--firmware uefi-secure-boot` when you want it configured as one thing.

**`--tpm` is what makes a VM attestable.** Without it there is no virtual TPM,
so the VM cannot produce a quote and `compute attest` has nothing to work with.
It defaults to off; on a trusted-computing platform you almost always want it
on.

```bash
platformctl compute create --name web-01 \
    --firmware uefi-secure-boot --tpm \
    --network-bridge br-tenant-a \
    --label tenant=tenant-a --label role=web \
    --start
```

### `compute list`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--all` | `-a` | bool | `false` | Show all VMs; **default shows only running** |
| `--filter` | `-f` | string array | | Filter (`key=value`), repeatable |

`list` without `--all` hides stopped VMs. A VM you created but did not start is
invisible by default.

### `compute delete`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--force` | `-f` | bool | `false` | Force delete a running VM |
| `--delete-disks` | | bool | `false` | Delete the associated disk images |

**Disks survive VM deletion unless you say otherwise.** That is the safe
default, and it is also how storage fills up.

### `compute stop`

`--force` stops the VM immediately rather than requesting a clean shutdown.

### `compute migrate`

| Flag | Short | Type | Meaning |
|---|---|---|---|
| `--destination` | `-d` | string | Destination daemon **mTLS gRPC endpoint** (`host:port`) — required |
| `--live` | | bool | Live migration; **requires shared storage** |

The destination is a daemon endpoint, not a hostname: migration goes
daemon-to-daemon over mTLS gRPC.

```bash
platformctl compute migrate web-01 --destination worker-02.example.com:9443 --live
```

---

## 3. `platformctl container`

| Verb | Positional | Purpose |
|---|---|---|
| `create` | — | Create a container |
| `list` | — | List containers |
| `get` | `<container-id>` | Container details |
| `start` | `<container-id>` | Start |
| `stop` | `<container-id>` | Stop |
| `remove` | `<container-id>` | Remove |
| `logs` | `<container-id>` | Get logs |
| `attest` | `<container-id>` | **Attest container integrity** |

### `container create`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--name` | `-n` | string | | Container name (**required**) |
| `--image` | `-i` | string | | Container image (**required**) |
| `--env` | `-e` | string array | | Environment variables (`KEY=value`) |
| `--label` | `-l` | string array | | Labels (`key=value`) |
| `--port` | `-p` | string array | | Port mappings (`hostPort:containerPort[/protocol]`) |
| `--mount` | `-m` | string array | | Volume mounts (`hostPath:containerPath[:ro]`) |
| `--privileged` | | bool | `false` | Run privileged |
| `--network-mode` | | string | | `bridge`, `host`, `none` |
| `--memory` | | string | | Memory limit, e.g. `512m`, `1g` |
| `--cpu` | | string | | CPU limit, e.g. `1`, `2`, `4` |
| `--cmd` | | string array | | Command to run |
| `--workdir` | `-w` | string | | Working directory |
| `--tpm-access` | | bool | `false` | **Mount the host TPM device into the container** |
| `--start` | | bool | `false` | Start immediately after creation |

**`--privileged` and `--tpm-access` are the two to think about.** `--privileged`
removes container isolation. `--tpm-access` gives the workload the *host's* TPM
device — not a virtual one — so it can perform operations with the host's root
of trust. Neither belongs in a default deployment.

```bash
platformctl container create --name api --image registry.example.com/apps/api:1.4.2 \
    --env LOG_LEVEL=info --port 8443:8443 --memory 1g --cpu 2 \
    --network-mode bridge --start
```

### `container list`

`--all` / `-a` shows all containers; the default shows only running.
`--filter` / `-f` is repeatable.

### `container logs`

| Flag | Short | Type | Default |
|---|---|---|---|
| `--follow` | `-f` | bool | `false` |
| `--timestamps` | `-t` | bool | `false` |
| `--stdout` | | bool | **`true`** |
| `--stderr` | | bool | **`true`** |

`--stdout` and `--stderr` both default to **true** — pass `--stdout=false` to
suppress one; passing `--stdout` alone changes nothing.

### `container remove`

`--force` / `-f` removes a running container; `--volumes` removes associated
volumes.

### `container attest`

`--nonce` (hex, generated when omitted) and `--pcrs` (comma-separated indices).
This is the **only attestation verb in the entire CLI** — see
[`docs/attestation/cli.md`](../attestation/cli.md).

---

## 4. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Suspend / resume a VM | QUIC, MCP |
| VM snapshots (create, list, delete, restore) | REST, gRPC, MCP |
| Disk attach / detach / resize | REST, gRPC, QUIC, MCP |
| VM metrics, container metrics | REST, gRPC, QUIC, MCP |
| Exec in a container | REST, gRPC, QUIC, MCP |
| Attest a VM | REST, gRPC, QUIC, MCP |
| Console attach | gRPC streaming only |
| Two-phase migration (`Prepare` / `Finalize`) | gRPC only |

---

## 5. Cloud providers need build tags

`compute create` against AWS, Azure or GCP requires the binary to be built with
`awscompute`, `azurecompute` or `gcpcompute`. Without the tag the call returns
"compute provider not compiled" (mapped to 501), which is a build fact, not a
runtime failure.

---

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
