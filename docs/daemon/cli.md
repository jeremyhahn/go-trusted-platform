# Platform Daemon — CLI

> **Status: NORMATIVE** · Scope: `platformctl` root verbs, global flags, `db`, `pkcs11`; the six binaries · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/root.go`, `pkg/cli/commands/root_pkcs11.go` and `cmd/` on 2026-10-11.
> The command tree was derived by building the binaries and walking `--help`:
>
> ```bash
> go build -tags "$(make -s print-build-tags)" -o platformctl ./cmd/platformctl
> go build -tags "$(make -s print-build-tags) pkcs11" -o platformctl-p11 ./cmd/platformctl
> ./platformctl --help; ./platformctl <verb> --help    # for every verb below
> ```
>
> This document is the one reference for the root of `platformctl` and for the
> daemon binaries. Feature groups are documented in their feature folders (§3).

---

## 1. Exit codes and output

These hold for every `platformctl` verb unless a section below says otherwise.

| code | meaning |
|---|---|
| `0` | Success. A parent group run with no subcommand (`platformctl service`) prints its help and exits 0. |
| `1` | Any error: bad flag, bad argument, unreachable daemon, failed RPC. `main.go` prints `Error: <message>` to stderr. |
| `2` | Panic. Only reachable today through the `-v` shorthand clash (§2.3). |

The root command sets `SilenceUsage`, so a failed verb prints only the error
line, not its usage.

**`--output json` is the parseable form.** The `table` renderer is for humans
and its columns are not a stable interface. `-o` is validated before any verb
runs:

```
$ platformctl -o xml version --client
Error: invalid output format: xml (valid: table, json, yaml)
```

Run with no arguments on a machine with a display, `platformctl` launches the
desktop GUI (§8); when the binary is built without the desktop tag it falls back
to the CLI help.

---

## 2. Global flags, contexts and transports

### 2.1 Global flags

Persistent flags on the root command, available to every verb. Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Type | Default | Environment | Meaning |
|---|---|---|---|---|---|
| `--config` | `-c` | string | `~/.platformctl/config.yaml` | `PLATFORMCTL_CONFIG` | CLI config file (§2.4). With no home directory, the system path is used. |
| `--context` | | string | the config's `current_context` | `PLATFORMCTL_CONTEXT` | Use this named context for one invocation |
| `--transport` | | string | from the context (§2.3) | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | string | from the context | `PLATFORMCTL_SERVER` | Server address; **implies a remote context** |
| `--server-name` | | string | | `PLATFORMCTL_SERVER_NAME` | TLS SNI and certificate-verification hostname |
| `--output` | `-o` | string | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | bool | `false` | | Verbose output |
| `--no-color` | | bool | `false` | `NO_COLOR` (any non-empty value) | Disable coloured output |

A config file that fails to load is fatal only when `--config` was given
explicitly; otherwise the built-in defaults are used. An unknown transport fails
before the verb runs:

```
$ platformctl --transport foo status
Error: invalid --transport "foo": must be one of unix, grpc, rest, quic, mcp, embedded
```

`--server-name` exists because the address you dial and the name on the
certificate are not always the same.

### 2.2 Which context a verb uses

1. `--context <name>` — that named context from the config file.
2. Otherwise `--server <addr>` — an ad-hoc **remote** context named `override`
   holding only that address: no CA, client certificate or token.
3. Otherwise the config's `current_context`. With no config file at all this is
   the built-in `local` context: Unix socket `/run/platformd.sock`.

`--server`, `--server-name` and `--transport` are then applied on top of
whichever context was chosen; `--server` also turns it into a remote context. To
reach a new address with a context's TLS material, combine the two:
`--context prod --server cp2.example.com:10443`.

### 2.3 Which transport a context uses

The first that is set wins: `--transport`, the context's `protocol`, the
context's `remote.protocol`. Otherwise the default follows the context type:

| Context type | Default transport |
|---|---|
| `local` | `unix` — gRPC over `/run/platformd.sock` |
| `remote` | `grpc` |
| `embedded` | `embedded` |

```bash
platformctl status                                          # local context, Unix socket
platformctl --server cp.example.com:10443 status            # ad-hoc remote, gRPC
platformctl --server cp.example.com:8443 --transport rest status
platformctl --server 192.0.2.10:9444 --server-name cp.example.com --transport quic status
platformctl --server https://cp.example.com:9445 --transport mcp status
```

**`embedded` hosts platformd inside platformctl.** The embedded transport
dispatches to service implementations held in a `ServiceRegistry`, so an
embedded context first starts platformd in the platformctl process
(`pkg/api/daemon/embedded_host.go`, the same host the desktop GUI's standalone
mode uses) and stops it when the command ends. Nothing listens on the network.
The host reads the platformd configuration from the locations platformd
searches, so on a node it runs with the node's own configuration and needs the
access platformd needs to its data and key stores. It loads the node's CA
as `platformd serve` does, initializing it on first use. A node without one
answers CA commands with `certificate authority not initialized`
([CA API](../ca/api.md) §4). Every call carries
platformctl's own process credentials, the identity it would have as a Unix
socket peer: root may do what root may over the socket, and any other uid is
refused what needs root (for example `ca sign-csr`, see
[CA authorization](../ca/api.md)).

```bash
sudo platformctl --transport embedded status
```

**Every verb that reaches a service needs a reachable daemon.** The verbs that
work with no daemon are `version --client`, `completion`, `context`, `wipe`,
`pkcs11` argument validation (§6), and the feature verbs that only touch local
files (for example `iso` and `diskimage` builds — see their feature docs).

**Short flags clash in two verbs.** `registry pull` declares `-v` for `--verify`
and `container remove` declares `-v` for `--volumes`, while the root already owns
`-v` for `--verbose`. Cobra cannot redefine a persistent shorthand: both verbs,
their `--help`, and `platformctl completion bash` (which walks every verb) panic
with exit 2 (`unable to redefine 'v' shorthand`). Local flags that reuse the
**long** name, such as `-o, --output` meaning a directory in `db dump` or a file
in `ca bundle`, are legal and shadow the global flag inside that verb. **Use
long forms in scripts.**

### 2.4 The config file

`platformctl` writes this file through `context add`, `context use` and
`context delete`, with mode `0600`. Keys are snake_case.

```yaml
current_context: prod
contexts:
  - name: local
    type: local                        # local | remote | embedded
    local:
      socket_path: /run/platformd.sock
  - name: prod
    type: remote
    protocol: grpc                     # optional; unix | grpc | rest | quic | mcp | embedded
    remote:
      server: cp.example.com:10443
      server_name: cp.example.com      # optional TLS SNI override
      ca_cert: /etc/platformctl/ca.pem
      client_cert: /etc/platformctl/client.pem
      client_key: /etc/platformctl/client-key.pem
      token: <bearer-token>            # optional; REST, MCP and QUIC
```

`local` also accepts `grpc_addr`, `quicbaas_addr` and `quicbaas_transport`;
`remote` also accepts `protocol`, `quicbaas_addr` and `quicbaas_transport`.

**The `context` verbs always write `~/.platformctl/config.yaml`,** whatever
`--config` says — see §4.6.

---

## 3. The command tree

`root.go` registers **44 top-level commands** in a default build: 11 root verbs
and 33 feature groups. A build with the `pkcs11` tag adds `pkcs11`
(`root_pkcs11.go`), for **45**. `help` is Cobra's own and is not counted.

### 3.1 Root verbs — documented here (§4)

`status`, `health`, `version`, `service`, `config`, `context`, `init`, `auth`,
`credential`, `completion`, `wipe`.

### 3.2 Feature groups — where each is documented

| Group | Reference |
|---|---|
| `acme`, `ca` | [`ca/cli.md`](../ca/cli.md) |
| `admin` | [`auth/cli.md`](../auth/cli.md) |
| `attestation` | [`attestation/cli.md`](../attestation/cli.md) |
| `authenticode`, `secure-boot` | [`firmware/cli.md`](../firmware/cli.md) |
| `barrier` | [`barrier/cli.md`](../barrier/cli.md) |
| `bmc` | [`bmc/cli.md`](../bmc/cli.md) |
| `bootstrap`, `firstboot` | [`bootstrap/cli.md`](../bootstrap/cli.md) |
| `ceremony` | [`cli/ceremony.md`](../cli/ceremony.md) |
| `compute`, `container` | [`compute/cli.md`](../compute/cli.md) |
| `db` | this document, §5 |
| `device`, `profile` | [`device/cli.md`](../device/cli.md) |
| `diskimage` | [`factory-image/cli.md`](../factory-image/cli.md) |
| `fido2` | [`cli/fido2.md`](../cli/fido2.md) |
| `iam` | [`iam/cli.md`](../iam/cli.md) |
| `install`, `iso` | [`installer/cli.md`](../installer/cli.md) |
| `kms` | [`kms/cli.md`](../kms/cli.md) |
| `luks` | [`luks/cli.md`](../luks/cli.md) |
| `ntp` | [`ntp/cli.md`](../ntp/cli.md) |
| `piv` | [`cli/piv.md`](../cli/piv.md) |
| `provision` | [`provisioning/cli.md`](../provisioning/cli.md) |
| `proxy` | [`proxy/cli.md`](../proxy/cli.md) |
| `registry` | [`registry/cli.md`](../registry/cli.md) |
| `sdn` | [`sdn/cli.md`](../sdn/cli.md); the gateway verbs in [`gateway/cli.md`](../gateway/cli.md) |
| `switch` | [`switch/cli.md`](../switch/cli.md) |
| `tenant` | [`tenant/cli.md`](../tenant/cli.md) |
| `tpm` | [`tpm/cli.md`](../tpm/cli.md) |
| `vtpm` | [`vtpm/cli.md`](../vtpm/cli.md) |
| `pkcs11` (`pkcs11` tag) | this document, §6 |

**There is no `dns`, no `pxe`, no `gateway` and no `cluster` top-level group.**
DNS has essentially no CLI ([`dns/cli.md`](../dns/cli.md)); PXE device lifecycle
is API-only; the gateway lives under `platformctl sdn gateway`. The secure-boot
group is spelled `secure-boot`.

---

## 4. Root verbs

### 4.1 `status`

Platform status and the state of each service, from the daemon.

- **Args:** none. **Flags:** none beyond the globals.
- **Exit:** 0, or 1 when the daemon cannot be reached.

```bash
platformctl status
platformctl -o json status
```

### 4.2 `health`

Health of the platform and its components.

- **Args:** none.
- **Flags:** `-d, --detailed` (bool, `false`) — per-component health.
- **Exit:** 0 whenever the daemon answers, **including when it reports
  unhealthy**; 1 when it cannot be reached. Gate on the status field, not on the
  exit code ([`health/cli.md`](../health/cli.md)):

```bash
test "$(platformctl -o json health | jq -r .status)" = healthy
platformctl health --detailed
```

### 4.3 `version`

Client version, and the server version when a daemon is reachable.

- **Args:** none.
- **Flags:** `--client` (bool, `false`) — client only; needs no daemon.
- **Exit:** 0; without `--client`, 1 when the daemon cannot be reached.

```bash
platformctl version --client
platformctl -o json version --client      # {"client_version": "..."}
```

### 4.4 `service`

Start, stop and inspect the daemon's services.

| Verb | Args | Flags |
|---|---|---|
| `service list` | none | none |
| `service status <service-type>` | exactly 1 | none |
| `service start <service-type>` | exactly 1 | none |
| `service stop <service-type>` | exactly 1 | `-f, --force` (bool, `false`): force the stop; `-t, --timeout` (uint32, `30`): seconds to wait |
| `service restart <service-type>` | exactly 1 | `-t, --timeout` (uint32, `30`): seconds to wait for the stop |

`<service-type>` is one of `tpm`, `sdn`, `compute`, `dns`, `acme`,
`webservice` (alias `web`), `attestation`.

- **Exit:** 0; 1 on a wrong argument count, an unknown type, an unreachable
  daemon or a failed operation.

```bash
platformctl service list
platformctl service restart dns --timeout 60
```

### 4.5 `config`

Read and change the **daemon's** running configuration. (The CLI's own config
file is managed with `context`, §4.6.)

| Verb | Args | Flags |
|---|---|---|
| `config get [section]` | 0 or 1 | none |
| `config set <section> <key=value>...` | 2 or more | `-p, --persist` (bool, `false`): write the change to the daemon's config file |
| `config reload` | none | none |

`config set` without `--persist` changes only the running daemon and warns
`Changes not persisted`. A pair without `=` fails with
`invalid key=value pair: <arg>`; the daemon must be reachable before the pairs
are applied.

- **Exit:** 0; 1 on a bad argument or an unreachable daemon.

```bash
platformctl -o yaml config get daemon
platformctl config set daemon log-level=debug --persist
platformctl config reload
```

### 4.6 `context`

Manage named connection contexts in the CLI config file (§2.4). Needs no
daemon.

| Verb | Args | Purpose |
|---|---|---|
| `context list` | none | Columns `CURRENT NAME TYPE PROTOCOL TARGET` |
| `context current` | none | Name, type, protocol, server and CA of the current context |
| `context use <name>` | exactly 1 | Make `<name>` current; `context not found: <name>` if absent |
| `context add <name>` | exactly 1 | Add a context; **replaces** an existing one of the same name |
| `context delete <name>` | exactly 1 | Remove it; clears `current_context` if it was current |

`context add` flags:

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--type` | `-t` | string | `local` | `local`, `remote` or `embedded` |
| `--server` | | string | | Server address; **required** for `remote`. Shadows the global `--server`. |
| `--protocol` | | string | auto (§2.3) | One of the six transports |
| `--socket-path` | | string | `/run/platformd.sock` | Unix socket, for `local` |
| `--ca-cert` | | string | | CA certificate file |
| `--client-cert` | | string | | Client certificate file (mTLS) |
| `--client-key` | | string | | Client key file (mTLS) |
| `--token` | | string | | Bearer token for REST, MCP and QUIC |

Errors: `--server is required for remote contexts`;
`invalid context type "<t>" (must be 'local', 'remote', or 'embedded')`; an
unknown `--protocol`.

**Known defects.** The writing verbs (`add`, `use`, `delete`) always save to
`~/.platformctl/config.yaml` and ignore `--config`. `list` and `current` always
print a table and ignore `-o`.

- **Exit:** 0; 1 on any error above.

```bash
platformctl context add prod --type remote --server cp.example.com:10443 \
  --ca-cert ca.pem --client-cert client.pem --client-key client-key.pem
platformctl context use prod
platformctl context list
```

### 4.7 `init`

Bootstrap a fresh platform in one call: initialises the barrier through the
SDK ceremony service and issues the first admin client certificate bundle.

- **Args:** none.

| Flag | Type | Default | Environment | Meaning |
|---|---|---|---|---|
| `--so-pin` | string | | `PLATFORMCTL_SO_PIN` | Security Officer PIN; **required** unless the strategy is `none` |
| `--user-pin` | string | | `PLATFORMCTL_USER_PIN` | User PIN; **required** unless the strategy is `none` |
| `--barrier-strategy` | string | `software` | `PLATFORMCTL_BARRIER_STRATEGY` | `software`, `shamir`, `pkcs11`, `tpm2`, `awskms`, `gcpkms`, `azurekv`, `vault`, `none` |
| `--shares` | int | | `PLATFORMCTL_SHARES` | Shamir share count; **required** for `shamir`, ≥ 2; rejected otherwise |
| `--threshold` | int | | `PLATFORMCTL_THRESHOLD` | Shamir threshold; **required** for `shamir`, 2 ≤ threshold ≤ shares; rejected otherwise |
| `--officer` | string, repeatable | | | Security Officer as `username=path/to/csr.pem`; **required** for `shamir`, exactly once per share; rejected otherwise ([`docs/bootstrap/cli.md`](../bootstrap/cli.md) §1a) |
| `--hostname` | string | | `PLATFORMCTL_HOSTNAME` | FQDN for the admin/server certificate CN |
| `--sans` | string | | `PLATFORMCTL_SANS` | Comma-separated extra DNS/IP SANs |
| `--admin-bundle` | string | `-` (stdout) | `PLATFORMCTL_ADMIN_BUNDLE` | Where to write the admin cert+key bundle; files are written `0600`. A directory is refused before `/init`; if the final rename fails the temporary file is kept and named in the error |
| `--force` | bool | `false` | | Overwrite an existing `--admin-bundle` file (refused otherwise) |

Backend-specific settings (HSM PINs, KMS key ARNs, Vault tokens) are daemon
configuration, not `init` flags. Prefer the environment variables to keep PINs
out of shell history.

- **Exit:** 0; 1 on a flag-validation error, e.g.
  `init: --so-pin is required (or set PLATFORMCTL_SO_PIN)`.

An unreachable gate or a refused `/init` fails the command with
`ErrInitStepFailed`, naming the step. The gate endpoint flags, the admin bundle
handling and retries are in [`docs/bootstrap/cli.md`](../bootstrap/cli.md) §1a.

```bash
PLATFORMCTL_SO_PIN=... PLATFORMCTL_USER_PIN=... \
  platformctl init --hostname cp.example.com --admin-bundle ./admin-bundle.pem
platformctl init --barrier-strategy shamir --shares 3 --threshold 2 \
  --officer alice=alice.csr --officer bob=bob.csr --officer carol=carol.csr \
  --so-pin "$SO_PIN" --user-pin "$USER_PIN"
```

### 4.8 `auth`, `admin` and `credential`

Documented in [`auth/cli.md`](../auth/cli.md). In short: `credential submit`,
`credential list` and `credential rotate` take free-form arguments and no flags,
and **every one of them fails** with
`credential <verb> is not yet wired to the SDK CredentialService` (exit 1).

### 4.9 `completion`

Prints a shell-completion script. Needs no daemon.

- **Args:** exactly one of `bash`, `zsh`, `fish`, `powershell`.
- **Flags:** none.
- **Exit:** 0; 1 with `accepts 1 arg(s), received 0` when no shell is named.
  **`bash` panics (exit 2)** because of the `-v` clash (§2.3); `zsh`, `fish` and
  `powershell` work.

```bash
platformctl completion zsh > "${fpath[1]}/_platformctl"
platformctl completion fish | source
```

### 4.10 `wipe`

Securely overwrites a LUKS container file or a block device, optionally followed
by TRIM/DISCARD so an SSD releases the blocks. The dracut hook runs it after a
successful firstboot to destroy the installer container
([`installer/cli.md`](../installer/cli.md)). Local; needs no daemon.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--path` | `-p` | string | | Device or container file; **required** |
| `--passes` | | int | `1` | Overwrite passes |
| `--random` | | bool | `false` | Random data instead of zeros |
| `--trim` | | bool | **`true`** | Issue `BLKDISCARD` after the wipe; `--trim=false` to skip |
| `--verbose` | `-V` | bool | `false` | Verbose output (capital `-V`; `-v` is the global `--verbose`) |

- **Args:** none.
- **Exit:** 0; 1 when `--path` is missing, the target cannot be locked, or a
  write fails.

```bash
platformctl wipe --path <install-dir>/installer.luks
platformctl wipe --path /dev/sdX2 --passes 3 --random
```

---

## 5. `db`

Inspect and export the daemon's QuicBaaS datastore through the SDK. Both verbs
need a reachable daemon; with none they fail with
`failed to connect to platformd: ...` (exit 1).

### 5.1 `db list`

Lists every entity type with its count.

- **Args:** none.
- **Flags:** `--config-dir` (string) — unused, kept for compatibility.
- **Output:** a header `QuicBaaS Entity Types (<path>)`, columns
  `ENTITY TYPE  COUNT  STATUS`, and a footer
  `Total: N entities across M active types`.
- **Exit:** 0; 1 on a connection or RPC error. Works over every transport.

```bash
platformctl db list
```

### 5.2 `db dump`

Exports entities to one file per entity, at
`<output>/<EntityType>/<id>.<format>`. The entity types are `Organization`,
`User`, `Registration`, `Role`, `WebAuthn`, `Device`, `DeviceProfile`, `Zone`.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--output` | `-o` | string | `./quicbaas-dump` | Output **directory**; shadows the global `-o` in this verb |
| `--format` | `-f` | string | `json` | `json` or `yaml` |
| `--entity-type` | `-t` | string | all | Only this type, e.g. `Zone` |
| `--pretty` | | bool | `false` | Indented output |
| `--config-dir` | | string | | Unused, kept for compatibility |

- **Args:** none.
- **Exit:** 0; 1 on a connection, RPC or write error.

**`db dump` is streaming and fails over REST:**
`db: failed to start dump: rpc error: code = Unimplemented desc = streaming not supported over REST transport`.
Use the Unix socket or gRPC. It prints `Connected to platformd` before the
dump call, so that line does not mean the dump started.

The examples in `platformctl db --help` still show a `--partition` flag; it no
longer exists. Use `--entity-type`.

```bash
platformctl db dump --output ./backup --format yaml --pretty
platformctl db dump --output ./backup --entity-type Zone
```

---

## 6. `pkcs11` (build tag `pkcs11`)

Present only when `platformctl` is built with the `pkcs11` tag. It is meant to
show PKCS#11 library, slot and token information for a module.

Persistent flags on the group:

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--module` | `-m` | string | | Path to the PKCS#11 module |
| `--ykcs11` | | bool | `false` | Use `/usr/local/lib/libykcs11.so` |
| `--softhsm2` | | bool | `false` | Use `/usr/local/lib/softhsm/libsofthsm2.so` |
| `--opensc` | | bool | `false` | Use `/usr/local/lib/opensc-pkcs11.so` |
| `--label` | `-l` | string | | Token label |
| `--slot` | `-s` | int | `-1` | Slot ID (`-1` = unset) |
| `--so-pin` | | string | | Security Officer PIN |
| `--pin` | | string | | User PIN |

- **Args:** none.

**It never performs an operation.** With no module selected it fails with
`invalid PKCS #11 module path: specify --module, --ykcs11, --softhsm2, or --opensc`;
with any module it fails with `daemon connection required`. Both exit 1, with or
without a daemon running. Use `kms` ([`kms/cli.md`](../kms/cli.md)) for
PKCS#11-backed key operations.

```bash
platformctl pkcs11 --softhsm2 --label platform --pin "$PIN"   # fails today: daemon connection required
```

---

## 7. The six binaries

| Binary | Run as | Reference |
|---|---|---|
| `platformd` | service | §7.1 |
| `gatewayd` | service | [`gateway/cli.md`](../gateway/cli.md) |
| `platformctl` | interactive | This document; CLI **and** desktop GUI in one binary (§8) |
| `pxeboot` | container entrypoint | [`ipxe/cli.md`](../ipxe/cli.md) |
| `platform-initrd` | **called by dracut** | [`installer/cli.md`](../installer/cli.md), [`bootstrap/cli.md`](../bootstrap/cli.md) |
| `deployer-pin` | interactive | §7.3 |

### 7.1 `platformd`

`platformd` is the control-plane **or** worker daemon — by configuration, not by
binary. Its commands are `serve`, `version` and `completion`; nothing else.
Run without a subcommand, `platformd` runs `serve` with that command's flag
defaults; only the persistent flags below are accepted in that form, so a unit
that sets `--socket-path` or a listener flag names `serve` explicitly.

Persistent flags:

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | string | | Platform config file |
| `--config-dir` | | string | `/etc/` | Configuration directory |
| `--platform-dir` | | string | `<cwd>/trusted-data` | Platform data directory |
| `--ca-dir` | | string | `trusted-data/ca` | CA directory |
| `--log-dir` | | string | `trusted-data/log` | Log directory |
| `--env` | `-e` | string | `dev` | Runtime environment: `dev`, `staging`, `prod` |
| `--debug` | `-d` | bool | `false` | Debug logging |
| `--debug-secrets` | | bool | `false` | Log secrets in debug output; never in production |
| `--init` | | bool | `false` | Initialise and provision the platform on start |
| `--intermediate` | | int | `1` | Index of the target intermediate CA |
| `--pin` | | bool | `false` | Supply the administrator/user PIN interactively |
| `--so-pin` | | bool | `false` | Supply the Security Officer PIN interactively |
| `--raw-pin` | | string | | User PIN, non-interactive |
| `--raw-so-pin` | | string | | Security Officer PIN, non-interactive |
| `--setuid` | | string | `root` | User to drop to when started as root. Parsed but not yet applied: no startup path calls `App.DropPrivileges`, which prepares the log file for that user while still root, then drops groups, GID and UID, and returns a typed error (user lookup, a UID/GID outside `0..4294967294`, log file, setgroups/setgid/setuid) rather than exiting; see [engineering.md](engineering.md) §5 |

`platformd serve` flags. Each bind host and port also has a config key
`daemon.<proto>.bind-host` / `daemon.<proto>.port`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--socket-path` | string | `/run/platformd.sock` | Unix socket |
| `--enable-grpc` | bool | `true` | gRPC listener. Under embedded quicbaas it requires `--enable-mtls` or platform tokens and is refused otherwise ([configuration](configuration.md#grpc-tcp-needs-mtls-or-platform-tokens-under-embedded-quicbaas)) |
| `--grpc-bind-host` / `--grpc-port` | string / int | `127.0.0.1` / `10443` | |
| `--enable-rest` | bool | `true` | REST listener. In daemon-only mode it requires `--enable-mtls` — its only authentication — and is refused otherwise |
| `--rest-bind-host` / `--rest-port` | string / int | `127.0.0.1` / `8443` | |
| `--enable-quic` | bool | `true` | QUIC listener |
| `--quic-bind-host` / `--quic-port` | string / int | `127.0.0.1` / `9444` | |
| `--enable-mcp` | bool | `true` | MCP listener |
| `--mcp-bind-host` / `--mcp-port` | string / int | `127.0.0.1` / `9445` | |
| `--enable-mtls` | bool | `false` | Mutual TLS on the network listeners |
| `--skip-iam-validation` | bool | `false` | Testing only |

**Barrier-unseal gate.** While the barrier is uninitialised or sealed,
`platformd serve` binds only the Unix socket and a loopback listener on
`127.0.0.1:9446` serving `GET /healthz`, `POST /init` and `POST /unseal`. The
production transports bind after the barrier is unsealed
([`bootstrap/`](../bootstrap/)). The barrier strategy is chosen by
`platformctl init --barrier-strategy` (§4.7), not by a `platformd` flag.

```bash
platformd serve --enable-mtls
platformd serve --enable-mtls --rest-bind-host 0.0.0.0 --grpc-bind-host 0.0.0.0
platformd version
```

#### Exit codes

`platformd serve` reports startup failure through its exit status, which a
service manager with `Restart=on-failure` depends on.

| code | meaning |
|---|---|
| `0` | The daemon started, ran, and shut down cleanly — signal-driven stop. This is the only path that exits 0. |
| `1` | Startup failed. The error names the phase; the cause follows it. |

**One code for every startup failure, deliberately.** The distinction a caller
could act on is *retryable* versus *permanent*, and that is not knowable where
these failures arise: a daemon that cannot start may be hitting a port conflict,
where a retry helps, or a bad configuration, where a retry never will. A code
scheme that cannot be populated accurately is worse than none, so the exit
status says only "startup failed" and the **error message** carries the detail:

```
platformd serve: daemon start: listen tcp 0.0.0.0:8443: bind: address already in use
platformd serve: barrier gate: init-only listener bind failed: 127.0.0.1:9446: listen tcp 127.0.0.1:9446: bind: address already in use
platformd serve: CA key store does not implement XKMSSigner
```

`1` rather than `2` because that is what `cmd/platformd` returns for every other
failure — a bad flag, an unknown subcommand — and one place decides it
(`main.go`) rather than each call site choosing. `platformd` with no subcommand
reports a failed startup the same way.

The contract is asserted against the running process, not by reading `main.go`:
`cmd/platformd/main_test.go` re-executes its test binary as `platformd` and
checks a successful command exits with this table's `0`, and that `serve` with an
unreadable config exits with its `1` and names the phase once on stderr. The
test reads the codes from this table, by the rows beginning "The daemon
started" and "Startup failed" — keep those openings if the wording changes.

### 7.2 `gatewayd`, `pxeboot`, `platform-initrd`

- **`gatewayd`** — `serve`, `version`, `completion`; global flags `--config`
  (`/etc/gatewayd/config.yaml`), `--config-dir` (`/etc/gatewayd`), `--data-dir`
  (`/var/lib/gatewayd`), `-d, --debug`, `--log-format` (`json`), `--log-level`
  (`info`). See [`gateway/cli.md`](../gateway/cli.md).
- **`pxeboot`** — Go `flag`-style options (`-manifest`, `-dhcp-server-ip`, ...);
  see [`ipxe/cli.md`](../ipxe/cli.md).
- **`platform-initrd`** — `boot`, `recovery`, `version`, `completion`. **Not
  user-facing; do not invoke it by hand.** `boot` unlocks the encrypted root
  with TPM-sealed keys; `recovery` handles boot failure. After `switch_root`,
  provisioning continues with `platformctl firstboot`. See
  [`installer/cli.md`](../installer/cli.md).

### 7.3 `deployer-pin`

Pins a host's SSH host key into a `known_hosts` directory. Despite the name it
provisions all three pin stores, which differ only in `--owner`:

| Surface | `--owner` | Guide |
|---------|-----------|-------|
| deployer | omitted (defaults to `--host`) | [`bootstrap/deployer.md`](../bootstrap/deployer.md#provisioning-the-pin) |
| physical switch | the switch `name` (omit when it has none) | [`bootstrap/switch-management.md`](../bootstrap/switch-management.md#provisioning-the-pin) |
| EVPN fabric (Nexus) | the fabric switch `id` | [`sdn/fabric/configuration.md`](../sdn/fabric/configuration.md#provisioning-the-host-key-pin) |

```
deployer-pin --host <ip> --dir <known_hosts_dir> \
  --expect-fingerprint SHA256:<...>[,SHA256:<...>] [--owner <owner>] [--port 22]
```

`--expect-fingerprint` is **mandatory**: there is no trust-on-first-use path.
Take the fingerprints from a channel other than the SSH connection being pinned
(the host console: `ssh-keygen -lf /etc/ssh/ssh_host_*.pub`, or the
provisioning record), and pass every one the host holds. A pin is rotated by
removing and re-adding it.

```bash
deployer-pin --host 192.0.2.20 --dir <install-dir>/known_hosts \
  --expect-fingerprint SHA256:<fingerprint>
```

---

## 8. `platformctl` is also the GUI

`cmd/platformctl/` holds one `bindings_*.go` per service surface, plus a
build-tagged `gui_desktop.go` / `gui_stub.go` pair and per-platform display
code.

The desktop window exposes the bindings `newGUIBindings`
(`cmd/platformctl/gui_bindings.go`) returns, all sharing one connection:
`ConnectionBinding`, `DaemonBinding` and `CABinding`. `CABinding.SignCSR` makes
the same SDK call as `platformctl ca sign-csr` and returns the object that
command prints with `--output json`; it is admin-only like the CLI
([docs/ca/api.md](../ca/api.md) §4). The other `bindings_*.go` files are not
yet bound to the window.

The GUI is compiled out by default. The consequence for anyone changing a
service surface: **the matching `bindings_*.go` must be updated or the GUI
silently lags the CLI.** That is what CLI/GUI feature parity means concretely
here.

---

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every `cli.md` verb to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists anywhere in this repository** (searched 2026-10-11).

That is a repo-level finding rather than a per-feature one, and it is recorded
in every converted feature folder so the next reader does not conclude the
requirement is met in some features and not others: it is met nowhere.
