# Bootstrap — CLI

> **Status: NORMATIVE** · Scope: `platformctl bootstrap`, `platformctl firstboot`, `platform-initrd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/bootstrap/`,
> `pkg/cli/commands/firstboot/` and `pkg/boot/commands/` on 2026-08-18.

---

## 1. Command groups

```
platformctl bootstrap            Platform bootstrap operations
platformctl bootstrap secrets    Manage bootstrap secrets
platformctl firstboot            First-boot TPM PCR sealing operations
platform-initrd boot             Unlock the encrypted root filesystem
platform-initrd recovery         Recovery mode with re-seal
```

`platformctl bootstrap` carries **three unrelated families** under one noun, and
mixing them up is the commonest mistake here:

| Family | Verbs | What it talks to |
|---|---|---|
| Day-zero fleet orchestration | `run`, `discover`, `deploy`, `status`, `teardown` | BMCs, the deployer host, the control plane |
| Trust bootstrap | `trust`, plus the canonical modes `auto`, `dane`, `noise`, `spki`, `direct` | A platform server's CA bundle endpoint |
| Secret migration | `secrets migrate`, `secrets verify`, `secrets status`, `secrets resolve` | A local configuration file and the KMS |

`platform-initrd` is **not user-facing**: its own help says so. It is invoked by
initramfs hooks. It is documented here because operators read its output when a
node fails to boot.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:126`), precedence
**flag > environment > config file > built-in default**:

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**`--config` at the root and `--config` on a bootstrap verb are different
files.** The root flag names the *platform* configuration; `bootstrap run
--config` names the *fleet description* (`bootstrap.yaml`). The local flag wins
inside the subcommand. Under `bootstrap secrets`, `--config` names yet a third
thing — the configuration file being rewritten.

**Which verbs need a running server.** None of the day-zero verbs talk to
`platformd` on a transport: they reach BMCs and the deployer host directly and
the control plane over plain HTTPS. `--transport` therefore has no effect on
them. `bootstrap secrets` needs a local KMS. `bootstrap trust` needs only the
target server's bundle endpoint. `platformctl firstboot` runs on the node itself
with no server at all.

---

## 2. `platformctl bootstrap run`

Execute the complete bootstrap flow. This is the verb that powers on hardware.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |
| `--dry-run` | bool | `false` | Validate config and test BMC connectivity; change nothing |
| `--skip-virtual-media-mount` | bool | `false` | For `boot_method: virtual-media` nodes, assume the operator inserted the media out of band |

```bash
platformctl bootstrap run --config ./bootstrap.yaml --dry-run
platformctl bootstrap run --config ./bootstrap.yaml
platformctl bootstrap run --config ./bootstrap.yaml --verbose
```

**Run `--dry-run` first, every time.** It validates the configuration, resolves
and prints the merged per-node device config, probes every BMC, reads each
reachable BMC's System Event Log, and prints the execution plan — including the
Cisco app-hosting commands when the deployer target is `cisco`. Nothing is
powered, mounted or written. A full event log or memory faults on record show up
under `Warnings:` naming the node and DIMM (`lab-node-2: DIMMB1 has 505 memory
faults on record …`) — fix or replace the part before provisioning, because a
failed DIMM halts POST and the install never starts.

**`--skip-virtual-media-mount` is an escape hatch, not a convenience.** It skips
only the mount step; boot-device selection, power reset, health wait and the
best-effort unmount still run. Use it on boards whose vendor mount API is behind
a licence the platform's BMC backends cannot drive, after inserting the ISO with
vendor tooling or the remote console.

Output on success is a result block naming the phase, the duration, per-stage
booleans, and a per-node table (hostname, role, MAC, BMC, status, error). On
failure the same block is printed **before** the error is returned, so a partial
run is still readable; the `Phase:` line names where it stopped.

---

## 3. `platformctl bootstrap discover`

Phase 0 only: query BMCs for MAC addresses and system info.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap discover --config ./bootstrap.yaml
```

Safe to run repeatedly — it opens BMC sessions and reads. It is the fastest way
to prove credentials and reachability before a real run, and the discovered MAC
set is the union of the ones declared in YAML and the ones the BMC reports.

---

## 4. `platformctl bootstrap deploy`

Deploy the bootstrap container to the configured host.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap deploy --config ./bootstrap.yaml
```

**This verb cannot currently succeed against a `linux` target.** The
`DeployConfig` it builds sets neither `manifest_path` nor `known_hosts_path`, so
the deployer rejects it at validation with
`ErrInvalidDeployConfig{Field:"manifest_path"}`, and would fail immediately
afterwards on the missing SSH host-key pins. Phase 2 of `bootstrap run` goes
through a different construction path that sets both. Use `bootstrap run` — with
`--dry-run` first — until this is fixed
([engineering.md](engineering.md) §7.6).

---

## 5. `platformctl bootstrap status`

Health-check every node in the configuration.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap status --config ./bootstrap.yaml
```

Prints a table of hostname, role, MAC, BMC-managed, health. Health is one of:

| Value | Means |
|---|---|
| `healthy` | `GET /api/v1/status` returned 200 **with a JSON body** |
| `unhealthy` | It answered, but with a non-200 status or a body that is not a platform response |
| `unreachable` | No candidate port answered |
| `unknown` | **No verified CA pool was available**, so no probe was attempted |

**What `healthy` measures, precisely.** `/api/v1/status` answers whenever the
node's webservice is serving; it carries no per-component verdict. So `healthy`
means *platformd is up and answering*, which is the question `bootstrap status`
exists to answer during node bring-up. A component-level reading — which
subsystem is degraded — lives at `/api/v1/platform/health` and requires an
authenticated `admin` (see [`docs/auth/architecture.md`](../auth/architecture.md)
§6c); this command holds no credential.

**The probe tries several ports**, because the webservice port depends on the
node's role: `8443` for control-plane and single-node, `9443` for compute, `443`
for gateway. They are tried in that order and the first port that *answers*
decides the verdict — an unreachable port says nothing about the others, but a
port that replies is that node's answer and ends the search.

**It grades on the body, not only the status code.** A status code alone cannot
tell platformd from a proxy, a load balancer, or a static file server that
answers 200 for everything. That is not hypothetical: before the SPA fallback
was closed for API paths, this command's probe was answered by `index.html` with
a 200 and reported **every node healthy regardless of its state** (#235).

`unknown` is not a network problem. It means the control plane's CA bundle could
not be fetched and verified, so the command refused to probe over an unverified
TLS connection and produce a green result it could not stand behind. A warning
naming the cause is printed to stderr.

---

## 6. `platformctl bootstrap teardown`

Remove the bootstrap container.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap teardown --config ./bootstrap.yaml
```

`bootstrap run` tears the container down itself, but only after every
control-plane node passes the health gate. When the gate fails, teardown is
skipped deliberately — the container may still be the only DHCP/DNS provider on
the provisioning network. This verb is how you tear down afterwards, once you
have confirmed the platform's own services took over.

---

## 7. `platformctl bootstrap trust`

Fetch the platform CA bundle over a strategy that does not need the CA bundle,
and optionally install it into the system trust store.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--server-url` | string | `""` | Platform server URL (**required**) |
| `--strategy` | string | `auto` | `auto`, `dane`, `noise`, `spki`, `embedded` |
| `--dns-server` | string | `""` | DNS server for DANE lookups; `host` or `host:port` |
| `--hostname` | string | `""` | Server hostname for the TLSA lookup — needed when `--server-url` is an IP |
| `--noise-key` | string | `""` | Noise_NK server static key, hex |
| `--noise-addr` | string | `""` | Noise server address, `host:port` |
| `--spki-pin` | string | `""` | Hex SHA-256 of the server SubjectPublicKeyInfo |
| `--bundle-path` | string | `""` | Bundle endpoint path override; empty selects the server default |
| `--install-to-system-trust` | bool | `false` | Write the bundle into the system trust store |
| `--cert-path` | string | `/usr/local/share/ca-certificates/platform-ca.crt` | Where to write it |
| `--per-method-timeout` | duration | `5s` | Timeout for each strategy attempt |

```bash
platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy auto \
    --install-to-system-trust

platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy dane --dns-server dns.example.com:8053 \
    --hostname platform.example.com

platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy spki --spki-pin <64-hex-sha256>
```

**`--strategy auto` is an ordered chain, not a probe.** It expands to `dane`,
`noise`, `spki` and stops at the first success. A single named strategy makes a
chain of one — a misconfigured `--strategy dane` fails rather than quietly
falling through to something weaker.

**`--dns-server` accepts a bare host and assumes port 53.** Platform control
planes do not bind privileged port 53 (the daemon runs unprivileged); their
resolver port is 8053. Pointing `--dns-server` at a control plane without a port
silently queries the wrong socket, so pass `host:8053` explicitly.

**`--per-method-timeout` defaults to 5 seconds**, not the 15 seconds several
example configurations in this folder use. Raise it for slow DNSSEC resolution.

**`--strategy embedded` fetches nothing** and prints "Using embedded CA bundle";
`--install-to-system-trust` has no effect in that mode.

`--install-to-system-trust` runs `update-ca-certificates` afterwards. A failure
there is a warning, not an error — the certificate file is already in place.

---

## 8. Canonical trust modes — `auto`, `dane`, `noise`, `spki`, `direct`

These are the locked cross-binary bootstrap surface — the shape
`<binary> bootstrap auto | dane | noise | spki | direct` is identical across
every daemon CLI in the stack, and the locked-surface specification (`docs/11`)
is the authority for it, not this file. All five verbs exist on `platformctl`.

| Verb | Args | Flags | State |
|---|---|---|---|
| `auto` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `dane` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `noise` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `spki` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `direct` | none | `--bundle` (string, path to a CA bundle PEM) | Implemented, narrowly |

```bash
platformctl bootstrap direct --bundle ./platform-ca.pem
```

The four stubs return an error telling you to use the key-management CLI's
`bootstrap <mode>` until the platform bridge ships. `direct` requires `--bundle`,
rejects a directory, and prints the accepted path and size — it validates that
the file is a readable regular file and does **not** parse the PEM, verify the
chain, or install anything. Use `bootstrap trust` for real work today.

This is a divergence between the locked surface and the implementation. It is
recorded here and in [engineering.md](engineering.md) §7.7 rather than
documented as if the stubs worked.

---

## 9. `platformctl bootstrap secrets`

Four verbs over a configuration file's secret URIs.

| Verb | Argument | Purpose |
|---|---|---|
| `migrate` | — | Rewrite plaintext secrets into KMS URIs |
| `verify` | — | Confirm every secret URI resolves |
| `status` | — | Report which secrets are present and how they resolve |
| `resolve` | `<uri>` | Resolve one URI |

**`migrate`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--dry-run` | bool | `false` | Preview without modifying the file |
| `--no-backup` | bool | `false` | Skip the timestamped backup |
| `--force` | bool | `false` | Continue even when some secrets fail to resolve |
| `--key-id` | string | `config-secrets` | KMS key used to encrypt migrated secrets |

**`verify`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--dry-run` | bool | `false` | Check resolver availability without resolving |
| `--fail-fast` | bool | `false` | Stop at the first failure |
| `--show-secrets` | bool | `false` | Print resolved values |

**`status`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--show-uris` | bool | `false` | Print masked secret URIs |

**`resolve <uri>`** — exactly one positional argument.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--masked` | bool | `true` | Mask the resolved value |
| `--raw` | bool | `false` | Print the full value |

```bash
platformctl bootstrap secrets status  --config <install-dir>/config.yaml
platformctl bootstrap secrets verify  --config <install-dir>/config.yaml
platformctl bootstrap secrets migrate --config <install-dir>/config.yaml --dry-run
platformctl bootstrap secrets migrate --config <install-dir>/config.yaml
platformctl bootstrap secrets resolve "kms://config/db/password"
```

**`--no-backup` and `--force` are both loaded.** `migrate` rewrites the file in
place; without a backup a bad run is unrecoverable, and `--force` writes KMS
references for secrets that did not resolve, which produces a configuration that
parses and then fails at startup.

**`--show-secrets` and `--raw` print secrets to your terminal**, which means into
your scrollback and possibly your shell history file. Prefer the masked default
and read the *status*, not the value.

Recognised URI schemes: `kms://`, `remote-kms://`, `env://`, `idevid://`,
`file://`, `dynamic://`, `xkms://`. A short `kms://` path is expanded into the
tenant/node keyspace automatically.

---

## 10. `platformctl firstboot`

Runs on the node, after `switch_root`, to seal the LUKS key into the TPM. It is
normally invoked by a service unit, not by hand.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--luks-device` | string | `""` | LUKS device path; auto-detected when empty |
| `--tpm-auto-unseal` | bool | `true` | Seal the key to the TPM |
| `--tpm-only` | bool | `false` | Remove the password keyslot after sealing |
| `--swtpm-state-dir` | string | `/var/lib/swtpm` | Software-TPM state directory |
| `--efi-mount` | string | `/boot/efi` | EFI partition mount point |
| `--pcrs` | uint slice | `nil` | PCRs to seal against; read from configuration when unset |
| `--config` | string | `""` | Platform configuration file |
| `--fips` | bool | `false` | Enable FIPS mode |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--debug` | bool | `false` | Debug logging |
| `--platform-dir` | string | `/var/lib/trusted-platform` | Platform data directory |
| `--config-dir` | string | `/etc/trusted-platform` | Configuration directory |
| `--log-dir` | string | `/var/log/trusted-platform` | Log directory |
| `--ca-dir` | string | `""` | CA data directory; defaults to `<platform-dir>/ca` |
| `--tpm-path` | string | `/dev/tpmrm0` | TPM device |
| `--xkms-dir` | string | `/etc/trusted-platform/xkms` | Key-management storage directory |

```bash
platformctl firstboot
platformctl firstboot --luks-device /dev/sda2
platformctl firstboot --luks-device /dev/sda2 --tpm-only
platformctl firstboot --pcrs 0,1,2,3,7
```

**There is no default PCR set.** With no `--pcrs` and no `seal-pcrs` in
configuration the command refuses to run rather than sealing against a guess.
Resolution order is `--pcrs`, then `seal-pcrs` / `tpm.seal-pcrs` /
`installer.seal-pcrs` in the first configuration file found.

`secure-wipe-passes` (top level, same files) sets how many overwrite passes
destroy `installer.luks` when a `TPM-PCR` unlock has proven the seal: 1 (the
default, NIST SP 800-88: one random pass plus TRIM), 3 (DoD 5220.22-M) or 7
(DoD ECE). It is read by `platform-initrd boot` before the container is
closed, and by firstboot for the failed-seal path.

**`--tpm-only` removes the password keyslot.** After that the disk unlocks only
via the TPM. If the PCR policy stops matching — firmware update, bootloader
change — the recovery key is the only way in.

**Exit codes carry meaning.** Zero means sealed. Non-zero with a
`FIRSTBOOT INCOMPLETE` message means LUKS was unlocked with the plain key but
sealing did **not** complete: the PCR banks file was not written and the daemon
will fail at startup. That is why the exit code is non-zero — so the service
manager does not mark itself started and first boot re-runs on the next boot.
The command tells you the usual cause (stale TPM owner-hierarchy auth) and the
usual fix.

Running it when there is nothing to do is safe: it prints "Firstboot sealing not
needed - system already configured" and exits zero.

---

## 11. `platform-initrd`

Called by initramfs hooks. Listed for the operator reading a failed boot.

```
platform-initrd boot       Unlock the encrypted root filesystem
platform-initrd recovery   Unlock with fallbacks and re-seal
platform-initrd version    Print version information
```

**`boot`**

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--device` | `-d` | string | | LUKS device path (**required**) |
| `--name` | `-n` | string | `cryptroot` | LUKS mapping name |
| `--timeout` | | int | `30` | Unlock timeout, seconds |
| `--pcrs` | | uint slice | `nil` | Expected PCR banks; read from the `pcr-banks` file when unset |
| `--fallback` | | bool | **`true`** | Enable fallback unlock methods |
| `--emergency` | | bool | `false` | Drop to an emergency shell on failure |
| `--tpm-path` | | string | `/dev/tpmrm0` | TPM device |
| `--efi-path` | | string | `/boot/efi` | EFI partition mount point |
| `--xkms-dir` | | string | `/etc/trusted-platform/xkms` | Key-management storage directory |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--debug` | | bool | `false` | Debug logging |
| `--fips` | | bool | `false` | FIPS mode — PBKDF2 instead of Argon2id |

**`recovery`** takes the same connection flags (`--device`, `--name`,
`--tpm-path`, `--efi-path`, `--xkms-dir`, `--verbose`, `--debug`, `--fips`) plus:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--reseal-pcrs` | bool | **`true`** | Re-seal to the current PCRs after unlocking |
| `--fido2` | bool | **`true`** | Allow a FIDO2 authenticator to unlock |
| `--interactive` | bool | `false` | Interactive recovery menu |

```bash
platform-initrd boot --device /dev/sda2
platform-initrd boot --device /dev/sda2 --timeout 60
platform-initrd recovery --device /dev/sda2 --interactive
```

**`--fallback` defaults to true**, which enables the ordered unlock chain
TPM-PCR → TPM-upgrade → FIDO2 → password. Disabling it makes a PCR mismatch
fatal.

**`recovery --reseal-pcrs` defaults to true**, so a successful recovery unlock
re-seals to whatever the PCRs are *now*. That is what you want after a firmware
or kernel change and emphatically not what you want if you have not established
why the measurements changed.

PCR resolution order for `boot`: `--pcrs`, then `<efi-path>/tpm2/pcr-banks`, then
`seal-pcrs` in a configuration file found inside the mounted installer container
or on the root filesystem.

---

## 12. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on failure,
with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface. The day-zero verbs print their own
fixed-width tables directly to stdout rather than going through the renderer, so
`--output json` does **not** change their shape.

`bootstrap run` returns non-zero when a phase fails, having already printed the
result block. A BMC-enrollment failure does not make the run non-zero — check
the `BMCEnrollments` entries in the output.

---

## 13. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Barrier init, unseal, seal, rekey, ceremony | `platformctl barrier` / `platformctl ceremony` — [`docs/cli/barrier.md`](../cli/barrier.md) |
| BMC enrollment outside a bootstrap run | `platformctl bmc` — [`docs/bmc/`](../bmc/) |
| Building or customising the ISO | `platformctl iso` — [`docs/provisioning/cli.md`](../provisioning/cli.md) |
| Device templates and profiles outside seeding | `platformctl device` — [`docs/device/`](../device/) |
| DANE TLSA record management | `platformctl dns` — [`docs/dns/cli.md`](../dns/cli.md) |
| Running bootstrap remotely | Nothing. There is no bootstrap service on any transport — [api.md](api.md) §5 |

---

## 14. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so that requirement
is unmet — repo-wide, not only for bootstrap.
