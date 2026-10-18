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
| `reboot` | `<vm-id>` | Reboot a VM (stop, then start) |
| `suspend` | `<vm-id>` | Pause a running VM in memory |
| `resume` | `<vm-id>` | Continue a suspended VM |
| `delete` | `<vm-id>` | Delete a VM |
| `migrate` | `<vm-id> --destination <host:port>` | Migrate to another host |

### `compute create`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--name` | `-n` | string | | VM name (**required**) |
| `--cpus` | | uint | `2` | vCPU cores |
| `--memory` | | uint | `2048` | Memory in MB |
| `--disk-size` | | uint | `20` | Boot disk size in GB |
| `--firmware` | | string | `uefi` | `bios`, `uefi`, `uefi-secure-boot` |
| `--secure-boot` | | bool | `false` | Enable UEFI Secure Boot |
| `--tpm` | | bool | `true` | Attach a virtual TPM 2.0 (vTPM); `--tpm=false` creates the VM without one |
| `--boot-device` | | string | `disk` | `disk`, `cdrom`, `network` |
| `--network-bridge` | | string | | Network bridge name |
| `--label` | `-l` | string array | | Labels (`key=value`), repeatable |
| `--start` | | bool | `false` | Start immediately after creation |

**The daemon applies every flag or refuses the create.** With the `local-qemu`
provider, `--firmware bios` and `--boot-device cdrom` are refused with
`code = InvalidArgument` naming the field, and so is a `--network-bridge` other
than the orchestrator's own; nothing is created. If `--start` cannot start the
VM, the daemon deletes it and the command fails with the start error. The full
list of what CreateVM honours and refuses is in
[api.md §2](api.md#2-vm-lifecycle).

**`--firmware` defaults to `uefi`, and `--secure-boot` does not.** Secure Boot
needs UEFI firmware. Use `--firmware uefi-secure-boot` when you want it
configured as one thing. Secure Boot also needs `ovmf_code_secure` in the
daemon's compute configuration.

**`--tpm` is what makes a VM attestable.** Without a virtual TPM the VM cannot
produce a quote and `compute attest` has nothing to work with. It is on by
default; `--tpm=false` is the way to leave it off.

```bash
platformctl compute create --name web-01 \
    --firmware uefi-secure-boot \
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

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--force` | | bool | `false` | Kill the VM at once instead of asking the guest to shut down |
| `--timeout` | `-t` | uint32 | `0` | Seconds the guest gets to shut down before it is terminated; `0` takes the daemon default (30), the maximum is 3600 |

`--force` and `--timeout` together are refused with InvalidArgument: a forced
stop does not wait.

### `compute reboot`

`--force` turns the VM off immediately instead of shutting it down cleanly;
the VM then starts again.

### `compute suspend` and `compute resume`

No flags. `suspend` needs a running VM and `resume` a suspended one; a VM in
the wrong state fails with the daemon's error (FailedPrecondition over gRPC,
QUIC and MCP; HTTP 400, read back as InvalidArgument, over REST).

### Transports

Every VM verb above reaches the daemon over `grpc`, `unix`, `rest`, `quic` and
`mcp`, each with its full request (`force`, `timeout_seconds` and
`delete_disks` included). Over `mcp` the `vm_*` tools take the RPC's full
request, so `--force`, `--timeout` and `--delete-disks` reach the daemon as
they do over gRPC.

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
| VM snapshots (create, list, delete, restore) | REST, gRPC, QUIC, MCP |
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
