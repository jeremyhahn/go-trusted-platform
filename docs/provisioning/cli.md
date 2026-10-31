# Zero-Touch Provisioning — CLI

> **Status: NORMATIVE** · Scope: `platformctl provision`, `install`, `iso` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/{provision,install,iso}/` on 2026-08-18.

---

## 1. Three command groups

```
platformctl provision    Device provisioning operations
platformctl install      System installation operations
platformctl iso          ISO build and test operations
```

BMC (`platformctl bmc`) and bootstrap (`platformctl bootstrap`) are part of the
same capability row and are **not documented in this pass** — see
[engineering.md](engineering.md) §1.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:134`), precedence
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

**`provision` verbs use `--server-url`, not the root's `--server`.** They run on
the machine being provisioned, which has no platform context and no credentials
yet, so they take an explicit URL.

---

## 2. `platformctl provision`

| Path | Purpose |
|---|---|
| `fetch-config` | Fetch provisioning config from the server |
| `interactive` | Interactive QR provisioning |
| `session list` | List active provisioning sessions |
| `session get <session-id>` | Get a session |
| `session poll <session-id>` | Poll a session once |
| `session fulfill <session-id>` | **Link a device profile to a pending session** |

### `provision fetch-config` and `provision interactive`

| Flag | Type | Required | Meaning |
|---|---|---|---|
| `--server-url` | string | **yes** | Provisioning server URL |
| `--ek-serial` | string | **yes** | Device EK serial number |
| `--mac` | string | **yes** | Device MAC address |
| `--eab-kid` | string | **yes** | EAB key ID |
| `--eab-hmac` | string | **yes** | EAB HMAC |
| `--output` | string | **yes** | Output path for the config YAML |
| `--timeout` | int | | Timeout in seconds (`interactive` only) |

All six are required. The identifying triple is what the machine **cannot
choose** — its EK serial and its MAC — plus an EAB credential issued to it out of
band ([`docs/eab/`](../eab/)).

**`--eab-hmac` is a credential on the command line.** It lands in shell history
and in the process table. Prefer a wrapper that reads it from a file or a
protected environment.

```bash
platformctl provision fetch-config \
    --server-url https://platform.example.com \
    --ek-serial 0x1A2B3C4D --mac 00:11:22:33:44:55 \
    --eab-kid kid-0f21 --eab-hmac "$EAB_HMAC" \
    --output /run/platform/config.yaml
```

### `provision session fulfill <session-id>`

| Flag | Type | Required | Meaning |
|---|---|---|---|
| `--profile-id` | string | **yes** | Device profile ID to link — **decimal uint64** |

**This is the authorisation step.** A device's session sits pending until an
operator links a device profile to it; there is no self-service path onto the
platform. `--profile-id` is a decimal `uint64`, not a name or a UUID.

```bash
platformctl provision session list
platformctl provision session get sess-9a3f
platformctl provision session fulfill sess-9a3f --profile-id 42
```

### `provision session poll <session-id>`

`--output` writes the delivered config JSON to a file. Poll is a **single**
poll, not a loop — the device side loops.

---

## 3. `platformctl install`

| Verb | Purpose |
|---|---|
| `system` | Install a complete operating system |
| `uki` | Build a Unified Kernel Image |
| `uki-rebuild` | **Rebuild and re-sign the UKI after a kernel update** |

**`uki-rebuild` changes what the machine measures at boot.** A new UKI produces
different PCR values, which invalidates anything sealed to them — vTPM-sealed
secrets, LUKS keys bound to PCRs, golden-PCR attestation policy. Plan the
re-seal and the policy update in the same maintenance window; the operation has
its own error file (`pkg/installer/uki_rebuild_errors.go`) because it has its own
failure modes.

---

## 4. `platformctl iso`

ISO build, customisation and test.

| Verb | Purpose |
|---|---|
| `build`, `create`, `customize`, `extract`, `download` | Image production |
| `test install`, `test boot`, `test firstboot`, `test pxe`, `test client-server`, `test all` | Test flows (all under `iso test`) |
| `module-signing-key` | Kernel module signing key |
| `profile list`, `profile show <profile-name>` | Installation profiles |
| `profile validate <config-file>` | Validate an installer configuration |
| `profile generate` | Generate a configuration |

**Run `iso profile validate <config-file>` before `iso build`.** An installer
configuration that fails validation at build time has already cost you the build.

---

## 5. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Register / list / get / remove a PXE device | REST `/api/v1/pxe/devices`, gRPC `PXEService`, QUIC, MCP |
| **Authorize / quarantine / retry** a PXE device | REST, gRPC, QUIC, MCP |
| Set a PXE device enrolled | REST, gRPC, QUIC, MCP |
| PXE device events | REST `GET /api/v1/pxe/devices/{id}/events`, gRPC `GetEvents`, QUIC, MCP |
| Start / stop the PXE service | REST, gRPC, QUIC, MCP |
| Remote Secure Boot digest signing | REST `POST /api/v1/provisioning/sign`, gRPC `SignDigest` (TCP and Unix socket), QUIC, MCP |

**There is no `platformctl pxe` command group.** Every PXE device-lifecycle
operation — including authorising and quarantining a device — is API-only. For a
capability whose whole point is bringing unknown machines onto a network safely,
that is worth noting; recorded as a gap in the migration report.

---

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide.

Additionally, two provisioning integration suites do not exercise what they
appear to. The PXE suite's adapters are real on every transport, but platformd
has no PXE backend, so every call answers `SERVICE_NOT_CONFIGURED`.
`test/integration/authenticode/multiprotocol_test.go` has all five protocol
adapters commented out. See [engineering.md](engineering.md) §7.
