# Device Identity, Profiles and Inventory — CLI

> **Status: NORMATIVE** · Scope: `platformctl device`, `platformctl profile` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/device/`
> and `pkg/cli/commands/profile/` on 2026-08-18.

---

## 1. Command groups

```
platformctl device            Device management operations
platformctl device profile    Device profile management
platformctl device attest-cert  The attestation certificate on a device record (§2.6)
platformctl profile           Device profile management (READ PATHS ARE STUBS — §6)
```

Both groups are registered on the root command
(`pkg/cli/commands/root.go:177` and `:187`). They are **not** the same group:
`device profile` writes through the SDK; the top-level `profile` group is
unimplemented. See §6 before using it.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:126`). Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Type | Default | Environment | Meaning |
|---|---|---|---|---|---|
| `--config` | `-c` | string | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | string | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | string | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | string | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | string | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | string | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | bool | `false` | | Verbose output |
| `--no-color` | | bool | `false` | `NO_COLOR` | Disable coloured output |

An invalid `--transport` is rejected before any command runs, with
`invalid --transport %q: must be one of unix, grpc, rest, quic, mcp, embedded`.

**Which verbs work without a server.** None of them, except through the
embedded transport. Every implemented verb builds a `cli.BaseCommand` and
speaks to a `DeviceServiceClient`. `--transport embedded` runs the services
in-process and is the only way to use them with no daemon listening.
`device register` is the one exception to context handling — it constructs its
own ad-hoc **REST** remote context from `--server`, because *"the device being
registered may not have a context configured yet."*

---

## 2. `platformctl device`

| Verb | Argument | Purpose |
|---|---|---|
| `list` | — | List devices, paginated |
| `get` | `<id>` | Get a device by id |
| `find-serial` | `<serial>` | Find a device by serial number |
| `register` | — | Create a device profile on a named control plane |
| `delete` | `<id>` | Delete a device by id |
| `profile` | — | Sub-group, §3 |

### 2.1 `device list`

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--page` | int | `1` | no | Page number, 1-indexed |
| `--page-size` | int | `20` | no | Items per page |

Table columns are `ID`, `SERIAL`, `MODEL`, followed by a
`Page N of M (Total: K devices)` line. `--output json` returns
`{page, page_size, total, total_pages, devices[]}`.

```bash
platformctl device list --page 2 --page-size 50
platformctl device list --output json
```

### 2.2 `device get <id>`

No local flags. `<id>` must parse as an unsigned decimal integer or the command
fails with `invalid device ID: <id>` before connecting.

Table output prints `ID`, `Serial`, `Model`, `Hash Algo`, and — when present —
truncated `EK Cert`, `Attest Pub` and `Signing`. JSON output omits the three
key fields entirely when empty.

```bash
platformctl device get 4398046511105 --output json
```

### 2.3 `device find-serial <serial>`

No local flags. An empty serial fails with `serial number is required`. A
lookup that returns no device fails with
`device not found with serial: <serial>`. Output format is identical to
`device get`.

```bash
platformctl device find-serial SRV-2024-001
```

### 2.4 `device register`

Creates a **device profile** on a control plane — the verb name is historical.
It does not create a `Device` record.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--hostname` | string | | **yes** | Device hostname; becomes the profile `Name` |
| `--mac` | string | | **yes** | MAC address; parsed with `net.ParseMAC` |
| `--role` | string | | **yes** | `control-plane`, `gateway`, or `worker` |
| `--template` | string | | **yes** | Template name, recorded in match-rule custom attributes |
| `--server` | string | | **yes** | Control plane URL |
| `--override-file` | string | | no | YAML file; validated as YAML, stored in the profile `event_log` field |
| `--ca-cert` | string | | no | CA certificate PEM path for TLS verification |

**`--role` here is a three-value set, and it is not the profile role set.**
`control-plane` maps to `DEVICE_ROLE_SERVER`, `gateway` to
`DEVICE_ROLE_GATEWAY`, `worker` to `DEVICE_ROLE_CLIENT`. The seven-value role
list in §3 belongs to `device profile create/update`. Passing `server` here
fails with `invalid role "server", must be one of: control-plane, gateway, worker`.

**`--override-file` contents land in `event_log`, not in a config field.** The
source says so: *"Override config bytes are stored in event_log until the proto
is regenerated with a dedicated config field."* Use
`device profile create --config-file` when you want a platform config
delivered.

```bash
platformctl device register \
    --hostname gw-01 \
    --mac 00:25:90:FF:AA:01 \
    --role gateway \
    --template gateway-default \
    --server https://cp.example.com:8443 \
    --ca-cert /etc/platform/ca.pem
```

### 2.5 `device delete <id>`

No local flags — **there is no `--force` and no confirmation prompt.** The help
text warns that the operation is irreversible; the command does not ask.

```bash
platformctl device delete 4398046511105
```

### 2.6 `device attest-cert record <id> [--reissue]`

Records — or re-records — the device's attestation (IAK/AK) certificate on
its platform record without re-enrolling the device ([api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473)).
It is the operator's step after the CA upgrade for a device enrolled before
the control plane recorded certificates (#447): the device's quotes are denied
until one is recorded.

The control plane fails closed and **the CLI has no override flag**: a
certificate is recorded only if it parses, chains to the platform CA, carries
`tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3) and certifies the device's
enrolled attestation key. Anything else is refused with a message naming every
candidate and the reason, and nothing is written — an unrestricted certificate
would quarantine the device on its next quote.

`--reissue` lets the platform CA issue a fresh certificate over the device's
enrolled attestation public key when nothing stored passes. The device is not
involved. Whether the CA stamps the attribute depends on the CA's own profile
(go-xkms ≥ 0.9.3 through go-quicbaas); a re-issued certificate without it is
refused like any other and the control plane revokes it in the same call so
the CA does not accumulate non-compliant attestation certificates. If that
revocation fails, the error names the serial and subject to revoke by hand.
The CA's profile cannot be probed beforehand, so pass the flag only once the
CA is known to comply.

```bash
platformctl device attest-cert record 4398046511105
platformctl device attest-cert record 4398046511105 --reissue -o json
```

Table output leads with `Attestation certificate recorded` or `… already
recorded; nothing changed`, then ID, Serial, Model, Source (`already on the
device record` / `platform CA certificate store (<name>)` / `re-issued by the
platform CA (<cn>)`), Reissued, Subject, Certificate Serial, Not After. JSON
output is the response of §4.5 with `id` in place of `device_id`. A refusal
exits non-zero with `attestation certificate not recorded for device <id>:
<control plane message>`.

After a successful record, the attestation collector's next sweep verifies a
quote against the new certificate and the device's report changes state
([attestation/user.md](../attestation/user.md)).

---

## 3. `platformctl device profile`

Six verbs: `get`, `list`, `create`, `update`, `assign`, `unassign`. All ride
the SDK device client (gRPC / Unix / QUIC / REST per the active context), so
the two read verbs confirm a write over the transport that made it — unlike
the top-level `platformctl profile` reads, which are stubs (§6, #460).

### 3.0 `device profile get <id>` and `device profile list`

```bash
platformctl device profile get 123
platformctl device profile get 123 --output json
platformctl device profile list                       # --page 1 --page-size 20
platformctl device profile list --page 2 --page-size 50 --output json
```

`get` renders the profile exactly as the write verbs do (§3.6). `list` prints
`ID`, `NAME`, `ROLE`, `ZONE`, `TLS SERVER NAME`, `ASSIGNED` and a page footer;
in `--output json` it is `{page, page_size, total, total_pages, profiles: [...]}`
with each item in the §3.6 shape. A non-numeric id fails with
`device profile: invalid profile ID: <id>`; a page or page size below one
fails with `device profile: invalid pagination: …` — both before connecting.

### 3.1 Shared field flags (`create` and `update`)

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--name` | string | | Profile name — **required on `create`** |
| `--model` | string | | Target device model |
| `--role` | string | | `control-plane`, `gateway`, `worker`, `server`, `client`, `workstation`, `edge`, `iot`, `load-balancer` (also accepts `unknown`) |
| `--zone` | string | | Default SDN zone for this profile |
| `--ek-serial` | string | | Exact TPM EK certificate serial for boot-time identity resolution |
| `--mac` | string | | Exact MAC address for non-TPM identification |
| `--ek-cert` | string | | Prestaged EK certificate: a PEM **file path** or an inline PEM string |
| `--config-file` | string | | Device platform config, YAML or JSON; converted to JSON on the wire |
| `--tls-server-name` | string | | Certificate name the attestation collector verifies nodes of this profile against when it dials them for a quote (e.g. `compute.example.internal`); empty means the device's own FQDN (`docs/attestation/user.md`) |

**`--ek-cert` decides path-versus-inline by looking for `-----BEGIN`.** A value
containing that marker is used verbatim; anything else is treated as a file
path. Either way the result must decode as a PEM block and parse as an X.509
certificate, or the command fails with
`EK certificate is not a valid PEM x509 certificate: <reason>` — before
connecting to the server.

**`--role` is optional on create.** An empty value maps to
`DEVICE_ROLE_UNSPECIFIED` so a minimal profile stays valid.

### 3.2 `device profile create`

```bash
platformctl device profile create --name worker-01 --role client

platformctl device profile create \
    --name node-02 \
    --role server \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem \
    --config-file /etc/platform/node-02.yaml
```

### 3.3 `device profile update <id>`

Positional `<id>` required. **Only the supplied flags change**; the command
fetches the profile, applies non-empty values, and writes it back. A
non-numeric id fails with `device profile: invalid profile ID: <id>`.

```bash
platformctl device profile update 123 --ek-cert /etc/platform/ek-certs/node-02.pem
platformctl device profile update 123 --config-file /etc/platform/node-02.yaml
platformctl device profile update 123 --tls-server-name compute.example.internal
```

**`--tls-server-name` survives an update that omits it** twice over: this
command writes back the fetched profile with only the named flags changed,
and the server restores the stored name when an update carries none. The
same holds for the read-only `pcr_baseline` the fetched profile carries: it
travels back unchanged and the server ignores it on the way in
(`docs/device/api.md` §3.6).

### 3.4 `device profile assign <profile-id>`

Binds a profile to a device identity.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--device` | string | | Registered device id to bind to; the **control plane** derives the EK serial from the device's stored EK certificate and prestages that certificate (#463) |
| `--ek-serial` | string | | EK certificate serial identifying the device |
| `--mac` | string | | Exact MAC address identifying the device |
| `--ek-cert` | string | | Prestaged EK certificate: PEM path or inline PEM |

**At least one of `--device`, `--ek-serial` or `--mac` is required**, checked
before connecting: `device profile: assignment requires --device, --ek-serial, or --mac`.

**`--device` is resolved on the control plane, not in the CLI.** The
command sends the device id; the daemon reads the device's stored EK
certificate, derives the serial (the decimal form of the X.509 serial number)
and prestages the certificate on the profile. The CLI never parses a
certificate. A device record with no EK certificate fails with
`device <id> has no EK certificate to derive an identity from; supply ek_serial or mac_address`
(gRPC `FAILED_PRECONDITION`, surfaced as `device profile: failed to assign
profile …`). A non-numeric or zero `--device` fails before connecting with
`invalid device ID: <value>`. **Explicit flags override derived values**, not
the other way round.

Binding is what makes the attestation collector and the quote verifier find
the profile for an enrolled device: their shared resolver prefers the bound
profile, then match rules (`docs/attestation/architecture.md`). Installer
profiles have neither, so assign each enrolled device once.

```bash
platformctl device profile assign 123 --device 4398046511105
platformctl device profile assign 123 \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem
```

### 3.5 `device profile unassign <profile-id>`

No flags. Clears EK serial, MAC, prestaged EK certificate and assignment state.

```bash
platformctl device profile unassign 123
```

### 3.6 Profile output

Every verb but `list` renders one profile. Table output prints `Profile ID`,
`Name`, and — when non-empty — `Model`, `Role`, `Zone`, `EK Serial`, `MAC`,
`EK Cert` (as `prestaged (PEM, N bytes)`), `Config` (as `N bytes (JSON)`),
`TLS Server Name`, `PCR Baseline` (as `<source> (N registers, recorded
<RFC3339>)`), and always `Assigned`. In `--output json` the same two appear as
`tls_server_name` and a `pcr_baseline` object (`values` hex by register index,
`source`, `recorded_at`, `recorded_from_device_id` as a decimal string).

**In `--output json` the profile `id` is a decimal string, not a number** —
`"id": "4398046511105"` — per the repo-wide convention for uint64 ids on the
wire. Parse it as a string.

---

## 4. `platformctl profile` — the top-level group

| Verb | Argument | Flags |
|---|---|---|
| `list` | — | `--page` (int, `1`), `--page-size` (int, `20`) |
| `get` | `<id>` | — |
| `delete` | `<id>` | — |
| `match` | — | `--mac`, `--serial`, `--model` (at least one required) |

`match` validates its arguments before dispatch:
`at least one of --mac, --serial, or --model is required`. `get` and `delete`
validate that `<id>` parses as an unsigned integer.

**Then all four fail.** See §6.

---

## 5. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on
failure, with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and
its columns are not a stable interface.

---

## 6. Defects and gaps in this surface

**The top-level `platformctl profile` group is a stub.** `runList`, `runGet`,
`runDelete` and `runMatch` in `pkg/cli/commands/profile/` each return
`ErrDaemonConnectionRequired{}` — *"daemon connection required"* —
**unconditionally**, with the comment *"Daemon connection required - dual-mode
will be added later."* No transport is attempted, so the failure is identical
whether or not a daemon is reachable and whether or not `--transport embedded`
is set. The typed errors `ErrProfileNotFound`, `ErrListProfilesFailed`,
`ErrGetProfileFailed`, `ErrDeleteProfileFailed`, `ErrMatchProfileFailed` and
`ErrNoMatchingProfile` are declared in that package and never returned.

Use `platformctl device profile get|list` for reads and
`platformctl device profile create|update|assign|unassign` for writes (§3);
matching and the by-MAC / by-serial lookups remain REST/gRPC/QUIC/MCP only
([api.md](api.md) §3) until the group is implemented (#460).

**No CLI verb covers**: device create/update (only `register`, which creates a
profile), profile delete, profile list, template CRUD, device activation, or
`find-config`. Reach those through the transports in [api.md](api.md).

**Parity gap.** `conventions/feature-docs.md` §4 requires every verb here to
have a matching `CommandDefinition` in the integration parity suite. **This
repository defines no `CommandDefinition` type** (grepped repo-wide,
2026-08-18), so the requirement is unmet repo-wide, not only for this feature.
It is recorded here rather than quietly marked satisfied.

---

## 7. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/cli.md`](../daemon/cli.md) — global flags and the `platformctl` command tree
