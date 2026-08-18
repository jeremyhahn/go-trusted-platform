# Platform Daemon — CLI

> **Status: NORMATIVE** · Scope: `platformctl` root verbs and global flags; the six binaries · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/root.go` and `cmd/` on 2026-08-18.

---

## 1. `platformctl` global flags

Persistent flags on the root command (`pkg/cli/commands/root.go:125`).
Precedence is **flag > environment > config file > built-in default** —
kubectl-style, and stated as such in the code.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Overrides current-context |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; **implies a remote context** |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

`--server-name` exists because the address you dial and the name on the
certificate are not always the same. `--server` implying a remote context is
worth remembering: it changes more than the address.

**`--output json` is the parseable form.** The `table` renderer is for humans
and its columns are not a stable interface.

**Short flags are shadowed in several groups.** `-v` is `--verbose` at the root
but `--verify` in `registry pull` and `--volumes` in `container remove`; `-o` is
`--output` format at the root but a file path in `ca bundle` and `vtpm export`;
`-f` is `--filter` in some `list` verbs and `--force` in some `delete` verbs.
Cobra resolves the local flag first. **Use long forms in scripts.**

---

## 2. Root-level verbs

`root.go` registers **41 top-level commands**. The ones that belong to the daemon
rather than to a feature:

| Verb | Purpose |
|---|---|
| `status` | Platform status |
| `health` | Platform health |
| `version` | Version |
| `service` | Service management |
| `config` | Configuration |
| `context` | Context management |
| `init` | Initialise |
| `auth` | Authentication |
| `credential` | Credentials |
| `completion` | Shell completion |
| `wipe` | Wipe |

The remaining 30 are feature groups: `acme`, `authenticode`, `barrier`, `bmc`,
`bootstrap`, `ca`, `ceremony`, `compute`, `container`, `db`, `device`, `fido2`,
`firstboot`, `iam`, `install`, `iso`, `kms`, `luks`, `ntp`, `piv`, `profile`,
`provision`, `proxy`, `registry`, `sdn`, `secureboot`, `switch`, `tenant`,
`tpm`, `vtpm`.

**There is no `dns`, no `attestation`, no `pxe`, no `gateway` and no `cluster`
top-level group.** DNS and attestation have essentially no CLI at all
([`docs/dns/cli.md`](../dns/cli.md), [`docs/attestation/cli.md`](../attestation/cli.md));
PXE device lifecycle is API-only; and the gateway lives under
`platformctl sdn gateway`.

---

## 3. Choosing a transport

```bash
platformctl --transport embedded status    # in-process, no daemon needed
platformctl --transport unix   status      # gRPC over a Unix socket
platformctl --transport rest   status
platformctl --transport quic   status
```

**`embedded` runs the services in-process** and is the only mode that works with
no daemon listening. Its reach is bounded by `ServiceRegistry`'s 22 service
fields — physical switch management, for instance, has no embedded route.

---

## 4. The six binaries

| Binary | Run as | Notes |
|---|---|---|
| `platformd` | service | Control-plane **or** worker — by configuration, not by binary |
| `gatewayd` | service | The edge role; [`docs/gateway/`](../gateway/) |
| `platformctl` | interactive | CLI **and** desktop GUI in one binary |
| `pxeboot` | container entrypoint | DHCP, TFTP and HTTP boot services |
| `platform-initrd` | **called by dracut** | **Not user-facing.** `boot` unlocks the encrypted root using TPM-sealed keys; `recovery` handles boot failure. After `switch_root`, provisioning continues via `platformctl firstboot` |
| `deployer-pin` | interactive | Deployer pin management; a pin is rotated by removing and re-adding it |

**Do not invoke `platform-initrd` by hand.** Its own doc comment says it is not
user-facing; it exists for the dracut hook.

---

## 5. `platformctl` is also the GUI

31 files in `cmd/platformctl/`, of which **22 are `bindings_*.go`** — one per
service surface — plus a build-tagged `gui_desktop.go` / `gui_stub.go` pair and
per-platform display code.

The GUI is compiled out by default. The consequence for anyone changing a
service surface: **the matching `bindings_*.go` must be updated or the GUI
silently lags the CLI.** That is what CLI/GUI feature parity means concretely
here.

---

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every `cli.md` verb to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists anywhere in this repository** (grepped 2026-08-18).

That is a repo-level finding rather than a per-feature one, and it is recorded
in every converted feature folder so the next agent does not conclude the
requirement is met in some features and not others: it is met nowhere. Raised as
an owner question in the migration report.
